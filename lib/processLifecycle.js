// Process-level safety for the production entry point only (tests build apps with
// createApplication and never install these handlers).
// - An unhandled promise rejection is logged as one structured line and the process
//   keeps serving; Node's default would crash it and drop every BayBay/SSE session.
// - SIGTERM/SIGINT (Render deploys and restarts) stop the background workers, stop
//   accepting connections, let in-flight requests finish for a bounded time, close
//   the database connection and exit.
const { describeFailure } = require('./serverErrors');

const defaultLog = line => console.error(JSON.stringify(line));

function installProcessHandlers({ application, disconnect = async () => {}, log = defaultLog, exit = code => process.exit(code),
  target = process, drainMs = 20000, forceMs = 25000 } = {}) {
  const onRejection = reason => {
    try { log({ level: 'error', event: 'unhandled_rejection', ...describeFailure(reason) }); } catch { /* never throw from here */ }
  };
  let closing = null;
  const shutdown = signal => {
    if (closing) return closing;
    closing = (async () => {
      log({ level: 'info', event: 'shutdown', signal });
      const force = setTimeout(() => { log({ level: 'error', event: 'shutdown_timeout', signal }); exit(1); }, forceMs);
      force.unref?.();
      application.sourceMonitor?.stop?.();
      application.notifications?.stop?.();
      // Long requests (BayBay streams) get drainMs to finish before their sockets are cut.
      const drain = setTimeout(() => application.server?.closeAllConnections?.(), drainMs);
      drain.unref?.();
      // Socket.IO disconnects its clients and closes the HTTP server, which waits
      // for in-flight requests and closes idle keep-alive connections.
      await new Promise(resolve => {
        if (application.io) application.io.close(() => resolve());
        else if (application.server) application.server.close(() => resolve());
        else resolve();
      });
      clearTimeout(drain);
      await disconnect();
      clearTimeout(force);
      log({ level: 'info', event: 'shutdown_complete', signal });
      exit(0);
    })().catch(failure => {
      try { log({ level: 'error', event: 'shutdown_failed', signal, ...describeFailure(failure) }); } catch { /* ignore */ }
      exit(1);
    });
    return closing;
  };
  const onTerm = () => { shutdown('SIGTERM'); };
  const onInt = () => { shutdown('SIGINT'); };
  target.on('unhandledRejection', onRejection);
  target.on('SIGTERM', onTerm);
  target.on('SIGINT', onInt);
  const uninstall = () => {
    target.off('unhandledRejection', onRejection);
    target.off('SIGTERM', onTerm);
    target.off('SIGINT', onInt);
  };
  return { shutdown, uninstall };
}

module.exports = { installProcessHandlers };
