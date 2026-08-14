-- CreateTable
CREATE TABLE "platform_meta" (
    "key" TEXT NOT NULL,
    "value" JSONB NOT NULL,
    "updated_at" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "platform_meta_pkey" PRIMARY KEY ("key")
);
