import { AuthService } from "./auth_service.ts";
import { loadConfig } from "./config.ts";
import { type IDatabase, SqliteDatabase } from "./database.ts";
import { startServer } from "./http_server.ts";
import { MysqlDatabase } from "./mysql_database.ts";

async function main(): Promise<void> {
  const cfg = loadConfig();
  if (cfg.jwtSecretIsEphemeral) {
    console.error(
      "[WARN] JWT_SECRET is not set; generated an ephemeral secret for this process.",
    );
  }

  let db: IDatabase;
  let dbDesc: string;

  if (cfg.dbDriver === "sqlite") {
    db = new SqliteDatabase(cfg.dbPath);
    dbDesc = `sqlite:${cfg.dbPath}`;
  } else if (cfg.dbDriver === "mysql") {
    db = new MysqlDatabase(
      cfg.mysqlHost,
      cfg.mysqlPort,
      cfg.mysqlUser,
      cfg.mysqlPassword,
      cfg.mysqlDatabase,
    );
    dbDesc = `mysql://${cfg.mysqlUser}@${cfg.mysqlHost}:${cfg.mysqlPort}/${cfg.mysqlDatabase}`;
  } else {
    throw new Error(
      `Unsupported DB_DRIVER: ${cfg.dbDriver} (expected mysql or sqlite)`,
    );
  }

  await db.initSchema();

  const authService = new AuthService(db, cfg);
  const server = startServer(authService, cfg.host, cfg.port);

  console.log(
    `Auth server listening on http://${cfg.host}:${server.port} (db=${dbDesc}, runtime=bun)`,
  );

  const shutdown = async () => {
    server.stop(true);
    await db.close();
    process.exit(0);
  };

  process.on("SIGINT", shutdown);
  process.on("SIGTERM", shutdown);
}

main().catch((err) => {
  console.error("Fatal error:", err instanceof Error ? err.message : err);
  process.exit(1);
});
