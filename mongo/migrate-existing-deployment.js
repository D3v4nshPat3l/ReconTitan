// Create or repair the ReconTitan application user on an EXISTING deployment.
//
// Why this file exists
// --------------------
// mongo/init/01-create-app-user.js runs only from
// /docker-entrypoint-initdb.d, which Mongo executes exactly once -- when the
// data directory is empty. Any deployment created before that script was added
// therefore has no application user, and none will ever be created: the volume
// is not empty, so the init hook never fires again. Those deployments keep
// running as the Mongo root user, which is precisely the privilege separation
// the init script was written to establish.
//
// This script is idempotent and safe to run repeatedly. It creates the user
// when absent, and updates the roles (and optionally the password) when the
// user exists but is wrong.
//
// Usage
// -----
//   docker compose exec -T mongo mongosh \
//     --username "$MONGO_ROOT_USER" --password "$MONGO_ROOT_PASS" \
//     --authenticationDatabase admin \
//     --eval "var APP_DB='recontitan', APP_USER='recontitan_app', APP_PASS='<password>', ROTATE=false" \
//     /docker-entrypoint-initdb.d/../migrate-existing-deployment.js
//
// Or, mounting this file directly:
//   docker compose cp mongo/migrate-existing-deployment.js mongo:/tmp/migrate.js
//   docker compose exec -T mongo mongosh -u "$MONGO_ROOT_USER" -p "$MONGO_ROOT_PASS" \
//     --authenticationDatabase admin \
//     --eval "var APP_DB='recontitan', APP_USER='recontitan_app', APP_PASS='<password>', ROTATE=false" /tmp/migrate.js
//
// Set ROTATE=true to reset the password of an existing user. Left false, an
// existing user's password is never touched, so running this against a healthy
// deployment cannot lock the application out.
//
// After it reports success, point the application at the app user and restart:
//   MONGO_USER=recontitan_app
//   MONGO_PASS=<password>
//   MONGO_AUTH_SOURCE=recontitan
//   docker compose up -d --force-recreate api worker

/* global db, APP_DB, APP_USER, APP_PASS, ROTATE, print, quit */

(function () {
  const dbName = typeof APP_DB !== "undefined" && APP_DB ? APP_DB : "recontitan";
  const user = typeof APP_USER !== "undefined" ? APP_USER : "";
  const password = typeof APP_PASS !== "undefined" ? APP_PASS : "";
  const rotate = typeof ROTATE !== "undefined" && ROTATE === true;

  if (!user || !password) {
    print("ERROR: APP_USER and APP_PASS must be supplied via --eval.");
    print("       Example: --eval \"var APP_USER='recontitan_app', APP_PASS='...'\"");
    quit(1);
  }

  const appDb = db.getSiblingDB(dbName);
  const wantedRoles = [{ role: "readWrite", db: dbName }];
  const existing = appDb.getUser(user);

  if (!existing) {
    appDb.createUser({ user: user, pwd: password, roles: wantedRoles });
    print("CREATED application user '" + user + "' with readWrite on '" + dbName + "'.");
  } else {
    // Compare only what this script is responsible for. A deployment that has
    // deliberately granted extra roles keeps them; the readWrite grant is added
    // if missing rather than replacing the whole set.
    const hasReadWrite = (existing.roles || []).some(
      (role) => role.role === "readWrite" && role.db === dbName
    );

    if (!hasReadWrite) {
      appDb.grantRolesToUser(user, wantedRoles);
      print("GRANTED readWrite on '" + dbName + "' to existing user '" + user + "'.");
    } else {
      print("OK: user '" + user + "' already holds readWrite on '" + dbName + "'.");
    }

    if (rotate) {
      appDb.updateUser(user, { pwd: password });
      print("ROTATED password for '" + user + "'. Update MONGO_PASS and restart api and worker.");
    }
  }

  // The application creates these itself on first write, but an existing
  // deployment may predate them. Creating them here is idempotent and keeps a
  // migrated database identical to a freshly initialised one.
  const scans = appDb.getCollection("scans");
  scans.createIndex({ scan_id: 1 }, { unique: true, name: "scan_id_unique" });
  scans.createIndex({ status: 1 }, { name: "status_idx" });
  scans.createIndex({ target: 1 }, { name: "target_idx" });
  scans.createIndex({ started_at: -1 }, { name: "started_at_desc" });
  print("Indexes on '" + dbName + ".scans' verified.");

  const rootUsers = db.getSiblingDB("admin").getUsers().users || [];
  if (rootUsers.length) {
    print("");
    print("REMINDER: the application must now authenticate as '" + user + "', not root.");
    print("          Set MONGO_USER / MONGO_PASS / MONGO_AUTH_SOURCE and recreate api and worker.");
  }
})();
