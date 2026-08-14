import { Module } from '@nestjs/common';
import { PrismaModule } from '../../prisma/prisma.module';
import { EvidenceController } from './evidence.controller';
import { EvidenceObjectStoreProvider } from './evidence-object-store.provider';
import { EvidenceRepository } from './evidence.repository';
import { EvidenceService } from './evidence.service';

@Module({
  imports: [PrismaModule],
  controllers: [EvidenceController],
  providers: [EvidenceRepository, EvidenceObjectStoreProvider, EvidenceService],
})
export class EvidenceModule {}
