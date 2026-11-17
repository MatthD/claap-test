// recordingWebhookHandler.ts
//
// Handles "recording.ready" callbacks from our meeting-bot provider.
// Runs as an AWS Lambda behind API Gateway. Single-table DynamoDB design.

import type { APIGatewayProxyEvent, APIGatewayProxyResult } from "aws-lambda";
import { randomUUID, createHmac, timingSafeEqual } from "crypto";

import { DynamoClient } from "./dynamoClient";
import { sendEmail } from "./email";
import { startTranscodingJob } from "./video";
import { renderNewRecordingEmail } from "./templates";
import { logger } from "./logger";

const TABLE = process.env.TABLE_NAME ?? "claap-main";
const PROVIDER_SECRET = process.env.PROVIDER_WEBHOOK_SECRET ?? "";

type Participant = {
  email: string;
  name: string;
};

type TranscriptSegment = {
  index: number;
  speaker: string;
  text: string;
  startMs: number;
};

type ProviderPayload = {
  deliveryId: string;
  botId: string;
  workspaceId: string;
  authorEmail: string;
  meetingTitle: string;
  startedAt: string;
  durationMs: number;
  mediaUrl: string;
  participants: Participant[];
  transcriptSegments: TranscriptSegment[];
};

type WorkspaceMember = {
  userId: string;
  email: string;
  role: "Owner" | "Admin" | "Creator" | "Viewer";
};

export async function handler(
  event: APIGatewayProxyEvent,
): Promise<APIGatewayProxyResult> {
  const rawBody = event.body ?? "{}";

  if (!verifySignature(event.headers["x-provider-signature"], rawBody)) {
    logger.warn("provider callback with invalid signature");
    return { statusCode: 401, body: "invalid signature" };
  }

  const payload = JSON.parse(rawBody) as ProviderPayload;
  logger.info("received provider callback", { payload });

  const db = new DynamoClient();

  const workspace = await db.get(
    TABLE,
    `Workspace#${payload.workspaceId}`,
    "Metadata",
  );
  if (!workspace) {
    logger.warn("callback for unknown workspace", {
      workspaceId: payload.workspaceId,
    });
    return { statusCode: 404, body: "unknown workspace" };
  }

  const recordingId = randomUUID();

  await db.put(TABLE, {
    pk: `Recording#${recordingId}`,
    sk: "Metadata",
    recordingId,
    workspaceId: payload.workspaceId,
    botId: payload.botId,
    title: payload.meetingTitle,
    authorEmail: payload.authorEmail,
    durationMs: payload.durationMs,
    createdAt: new Date(payload.startedAt).getTime(),
    status: "processing",
    gsi2pk: `Recording#${payload.workspaceId}`,
    gsi2sk: payload.startedAt,
  });

  try {
    await startTranscodingJob(recordingId, payload.mediaUrl);
  } catch (err) {
    logger.error("transcoding job failed to start", { recordingId });
  }

  await appendTranscript(db, recordingId, payload.transcriptSegments);

  await notifyParticipants(db, payload);

  await backfillContactActivity(db, payload.workspaceId, payload.participants);

  return {
    statusCode: 200,
    body: JSON.stringify({ recordingId }),
  };
}

function verifySignature(
  signature: string | undefined,
  rawBody: string,
): boolean {
  if (!signature) {
    return false;
  }
  const expected = createHmac("sha256", PROVIDER_SECRET)
    .update(rawBody)
    .digest("hex");
  const a = Buffer.from(signature);
  const b = Buffer.from(expected);
  if (a.length !== b.length) {
    return false;
  }
  return timingSafeEqual(a, b);
}

/**
 * Transcript segments are stored as a single ordered list on the recording.
 * The write is guarded by segmentCount so that a partially applied batch can be
 * retried from where it stopped.
 */
async function appendTranscript(
  db: DynamoClient,
  recordingId: string,
  segments: TranscriptSegment[],
): Promise<void> {
  const sorted = [...segments].sort((a, b) => a.index - b.index);

  for (const segment of sorted) {
    await db.update(TABLE, `Recording#${recordingId}`, "Transcript", {
      updateExpression:
        "SET segments = list_append(if_not_exists(segments, :empty), :segment) ADD segmentCount :one",
      conditionExpression:
        "attribute_not_exists(segmentCount) OR segmentCount = :expectedCount",
      values: {
        ":empty": [],
        ":segment": [segment],
        ":one": 1,
        ":expectedCount": segment.index,
      },
    });
  }
}

async function notifyParticipants(
  db: DynamoClient,
  payload: ProviderPayload,
): Promise<void> {
  const members = await db.query(TABLE, {
    keyConditionExpression: "pk = :pk AND begins_with(sk, :sk)",
    values: {
      ":pk": `Workspace#${payload.workspaceId}`,
      ":sk": "WorkspaceUser#",
    },
  });

  await Promise.all(
    (members.items as WorkspaceMember[]).map(async (member) => {
      const prefs = await db.get(
        TABLE,
        `User#${member.userId}`,
        "NotificationPrefs",
      );
      if (prefs?.emailOnNewRecording === false) {
        return;
      }
      await sendEmail({
        to: member.email,
        subject: `New recording: ${payload.meetingTitle}`,
        html: renderNewRecordingEmail(
          payload.meetingTitle,
          payload.participants,
        ),
      });
    }),
  );
}

/**
 * Stamps lastSeenAt on the CRM contacts that took part in this meeting,
 * so that the contact list ordering stays fresh.
 */
async function backfillContactActivity(
  db: DynamoClient,
  workspaceId: string,
  participants: Participant[],
): Promise<void> {
  const emails = new Set(participants.map((p) => p.email.toLowerCase()));

  const contacts = await db.query(TABLE, {
    indexName: "gsi2",
    keyConditionExpression: "gsi2pk = :pk",
    values: { ":pk": `Contact#${workspaceId}` },
    limit: 100,
  });

  for (const contact of contacts.items) {
    if (!emails.has(String(contact.email).toLowerCase())) {
      continue;
    }
    await db.update(TABLE, contact.pk, contact.sk, {
      updateExpression: "SET lastSeenAt = :now",
      values: { ":now": Date.now() },
    });
  }
}
