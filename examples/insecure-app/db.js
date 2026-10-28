// A stand-in for a real database client: records the SQL it would run.
export const executed = [];
const db = { query: async (sql) => executed.push(sql) };

export async function saveCompany({ refreshToken, realmId }) {
  await db.query(`INSERT INTO companies (realm_id, refresh_token) VALUES ('${realmId}', '${refreshToken}')`);
}
