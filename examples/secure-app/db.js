// A stand-in for a real database client: records parameterized statements.
export const executed = [];
const db = { query: async (sql, params) => executed.push({ sql, params }) };

export async function saveCompany({ refreshToken, realmId }) {
  await db.query('INSERT INTO companies (realm_id, refresh_token) VALUES ($1, $2)', [realmId, refreshToken]);
}
