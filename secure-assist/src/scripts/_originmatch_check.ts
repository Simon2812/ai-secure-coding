import { findOriginRange, containsOrigin } from '../model/originMatch';
import * as fs from 'fs';

const code = fs.readFileSync(
  'C:/Users/משתמש/Desktop/test/scan-demo/backend/UserDao.java',
  'utf-8'
);

// Exactly what the model returned for UserDao.java (note: no indentation
// before `return`, which is why the old exact match failed).
const origin =
  'String query = "SELECT * FROM users WHERE name = \'" + name + "\'";\nreturn stmt.executeQuery(query);';

console.log('old exact match  :', code.includes(origin));
console.log('new fuzzy match  :', containsOrigin(code, origin));

const range = findOriginRange(code, origin);
if (range) {
  console.log(`\nmatched chars ${range.start}-${range.end}`);
  console.log('--- matched text from the real file ---');
  console.log(code.slice(range.start, range.end));
} else {
  console.log('NO MATCH');
}
