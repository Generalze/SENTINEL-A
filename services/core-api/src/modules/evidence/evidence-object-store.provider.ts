import type { Readable } from 'node:stream';
import { Inject, Injectable, Logger, type OnModuleInit } from '@nestjs/common';
import { CreateBucketCommand, DeleteObjectCommand, GetObjectCommand, HeadBucketCommand, PutObjectCommand, S3Client, S3ServiceException } from '@aws-sdk/client-s3';
import { AppConfigService } from '../../config/config.service';
import { OBJECT_KEY_SEPARATOR } from './evidence.constants';

/**
 * S3-API (MinIO) client wrapper for the evidence vault (WP-09 deliverable
 * 1; architecture §72.1 storage split). `forcePathStyle: true` is required
 * against a local MinIO endpoint — virtual-hosted-style bucket addressing
 * (the AWS SDK v3 default) does not resolve there.
 *
 * Bucket creation is idempotent: `ensureBucket()` HEADs the bucket first
 * and only issues `CreateBucket` when that fails, and separately tolerates
 * "someone else (or an earlier call in this same process) created it a
 * moment ago" (`BucketAlreadyOwnedByYou`/`BucketAlreadyExists`) rather than
 * treating that race as a fatal boot error. `onModuleInit` runs this once
 * at application boot; `putObject`/`getObject` also call it defensively so
 * direct construction in a unit test (bypassing Nest's lifecycle, the same
 * pattern this repo's other provider tests use — see nats.provider.spec.ts)
 * never skips it.
 */
@Injectable()
export class EvidenceObjectStoreProvider implements OnModuleInit {
  private readonly logger = new Logger(EvidenceObjectStoreProvider.name);
  private readonly client: S3Client;
  private readonly bucket: string;
  private ensured = false;
  private ensuring: Promise<void> | undefined;

  constructor(@Inject(AppConfigService) private readonly appConfig: AppConfigService) {
    const { S3_ENDPOINT, S3_ACCESS_KEY, S3_SECRET_KEY, S3_REGION, S3_EVIDENCE_BUCKET } = this.appConfig.values;
    this.bucket = S3_EVIDENCE_BUCKET;
    this.client = new S3Client({
      endpoint: S3_ENDPOINT,
      region: S3_REGION,
      forcePathStyle: true,
      credentials: { accessKeyId: S3_ACCESS_KEY, secretAccessKey: S3_SECRET_KEY },
    });
  }

  /** Deliverable 1: bucket created idempotently at boot. */
  async onModuleInit(): Promise<void> {
    await this.ensureBucket();
  }

  async ensureBucket(): Promise<void> {
    if (this.ensured) return;
    if (!this.ensuring) {
      this.ensuring = this.doEnsureBucket().finally(() => {
        this.ensuring = undefined;
      });
    }
    await this.ensuring;
  }

  private async doEnsureBucket(): Promise<void> {
    if (this.ensured) return;
    try {
      await this.client.send(new HeadBucketCommand({ Bucket: this.bucket }));
      this.ensured = true;
      return;
    } catch {
      // Any HeadBucket failure (missing bucket, transient auth quirk against
      // MinIO, ...) falls through to an idempotent create attempt below.
    }

    try {
      await this.client.send(new CreateBucketCommand({ Bucket: this.bucket }));
      this.logger.log(`created evidence bucket "${this.bucket}"`);
    } catch (error) {
      if (!isAlreadyOwned(error)) {
        this.logger.error(`failed to ensure evidence bucket "${this.bucket}": ${String(error)}`);
        throw error;
      }
      // Already exists (created by an earlier call, or another process) — idempotent by definition.
    }
    this.ensured = true;
  }

  /** `{organisation_id}/{evidence_id}` — deliverable 1's per-organisation key prefix. */
  objectKeyFor(organisationId: string, evidenceId: string): string {
    return `${organisationId}${OBJECT_KEY_SEPARATOR}${evidenceId}`;
  }

  /**
   * Writes `content` to `objectKey`. There is deliberately no
   * "replace"/"overwrite" method anywhere on this provider or on
   * EvidenceService — every production write path always computes a
   * brand-new objectKey first (see EvidenceService.ingest/derive), so
   * nothing in this module ever calls putObject twice against the same
   * key (deliverable 2's "no update path for originals" requirement;
   * enforced by test, not by this method refusing a second write, so the
   * AC3 tamper-detection test can still simulate an attacker overwriting
   * an existing key directly through this same client).
   */
  async putObject(objectKey: string, content: Buffer, contentType: string): Promise<void> {
    await this.ensureBucket();
    await this.client.send(
      new PutObjectCommand({
        Bucket: this.bucket,
        Key: objectKey,
        Body: content,
        ContentType: contentType,
      }),
    );
  }

  async getObject(objectKey: string): Promise<Buffer> {
    await this.ensureBucket();
    const result = await this.client.send(new GetObjectCommand({ Bucket: this.bucket, Key: objectKey }));
    return streamToBuffer(result.Body as Readable);
  }

  /** Compensation ONLY for this caller's just-uploaded object after its DB
   * insert lost a unique race. Never accepts a committed Evidence id/key. */
  async removeUncommittedObject(objectKey: string): Promise<void> {
    await this.client.send(new DeleteObjectCommand({ Bucket: this.bucket, Key: objectKey }));
  }
}

async function streamToBuffer(stream: Readable): Promise<Buffer> {
  const chunks: Buffer[] = [];
  for await (const chunk of stream) {
    chunks.push(Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk as Uint8Array));
  }
  return Buffer.concat(chunks);
}

function isAlreadyOwned(error: unknown): boolean {
  if (error instanceof S3ServiceException) {
    return error.name === 'BucketAlreadyOwnedByYou' || error.name === 'BucketAlreadyExists';
  }
  return false;
}
