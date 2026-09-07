import { Inject, Injectable, Logger, Module, type OnApplicationShutdown, type Provider } from '@nestjs/common';
import { EdgeConfigService } from '../../config/config.service';
import { SqliteEdgeOperationStore } from './edge-queue.store';

/** DI token for the durable operation store. */
export const EDGE_OPERATION_STORE = Symbol('EDGE_OPERATION_STORE');

/**
 * Opens the store at boot, from `EDGE_QUEUE_PATH` and nothing else.
 *
 * NO CAPACITY, NO RETENTION AND NO CLOCK ARE PASSED. Those are the store's
 * constructor's test seams, and the production path deliberately takes the
 * hard-wired defaults: an Edge whose queue depth or retention could be set from
 * the environment is an Edge whose willingness to hold a Field operative's work
 * is editable by whoever last touched the file in the wiring closet.
 *
 * OPENING AT BOOT, NOT LAZILY, IS THE POINT. `SqliteEdgeOperationStore`'s
 * constructor refuses a database it cannot trust — wrong schema version, an
 * entry at or beyond the counter — by throwing, and Nest turns that into a
 * failed bootstrap. An Edge with an unreadable queue must not come up
 * half-working and start accepting operations it cannot keep; it must fail to
 * start, loudly, where an operator sees it.
 */
export const EDGE_OPERATION_STORE_BINDING: Provider = {
  provide: EDGE_OPERATION_STORE,
  inject: [EdgeConfigService],
  useFactory: (config: EdgeConfigService) => new SqliteEdgeOperationStore({ directory: config.values.EDGE_QUEUE_PATH }),
};

/**
 * Closes the database on shutdown.
 *
 * A SEPARATE PROVIDER RATHER THAN A LIFECYCLE HOOK ON THE STORE, so the store
 * stays a plain class any test can construct without a Nest container — the
 * same argument `EdgeTrustedTimeAnchor` makes for not being a provider.
 *
 * Closing matters even though every transaction is already durable: a clean
 * close checkpoints and removes the WAL sidecar, so the next boot opens a
 * single file rather than replaying a journal. An unclean exit is safe — that
 * is what the journal is for — but it is not the state to leave behind on
 * purpose.
 */
@Injectable()
export class EdgeQueueShutdownHook implements OnApplicationShutdown {
  private readonly logger = new Logger(EdgeQueueShutdownHook.name);

  constructor(@Inject(EDGE_OPERATION_STORE) private readonly store: SqliteEdgeOperationStore) {}

  onApplicationShutdown(): void {
    try {
      this.store.close();
    } catch (error) {
      // A close that fails changes nothing about what is on the disk, and a
      // service that refused to shut down would be worse than one that logged.
      this.logger.warn(`closing the durable queue failed: ${String(error)}`);
    }
  }
}

/**
 * The durable queue.
 *
 * NO CONTROLLER, following `EdgeTrustedTimeModule`. This module adds no HTTP
 * surface: a route that let anything on the site LAN enqueue, inspect or drain
 * a queue full of Field operations would be an unauthenticated door into every
 * operative's activity on the site. The authenticated ingress that puts
 * operations here is another lane's, and it takes this store as a dependency
 * rather than this module taking a controller.
 */
@Module({
  providers: [EDGE_OPERATION_STORE_BINDING, EdgeQueueShutdownHook],
  exports: [EDGE_OPERATION_STORE],
})
export class EdgeQueueModule {}
