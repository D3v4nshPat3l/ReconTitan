const appDbName = process.env.MONGO_APP_DB || "recontitan";
const appUser = process.env.MONGO_APP_USER;
const appPassword = process.env.MONGO_APP_PASS;

if (!appUser || !appPassword) {
  throw new Error("MONGO_APP_USER and MONGO_APP_PASS are required");
}

const appDb = db.getSiblingDB(appDbName);
if (!appDb.getUser(appUser)) {
  appDb.createUser({
    user: appUser,
    pwd: appPassword,
    roles: [{ role: "readWrite", db: appDbName }],
  });
}
