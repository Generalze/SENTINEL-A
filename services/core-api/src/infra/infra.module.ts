import { Module } from '@nestjs/common';
import { NatsProvider } from './nats.provider';
import { RedisProvider } from './redis.provider';

@Module({
  providers: [NatsProvider, RedisProvider],
  exports: [NatsProvider, RedisProvider],
})
export class InfraModule {}
