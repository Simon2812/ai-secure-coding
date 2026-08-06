import { initAstAnalyzer, astAnalyzeCode } from '../../analyzer/ast/astAnalyzer';
import * as fs from 'fs';

// expectCwes: empty = SAFE (expect no findings), otherwise expect ALL listed CWEs detected
const TEST_FILES: { path: string; expectCwes: string[] }[] = [
  // ── Python ──────────────────────────────────────────────────────────────────
  { path: 'C:/temp/fresh50/python/vuln_sqli_fstring.py',       expectCwes: ['CWE-89']           },
  { path: 'C:/temp/fresh50/python/vuln_cmd_injection.py',      expectCwes: ['CWE-78']           },
  { path: 'C:/temp/fresh50/python/vuln_path_traversal.py',     expectCwes: ['CWE-22']           },
  { path: 'C:/temp/fresh50/python/vuln_hardcoded_db_cred.py',  expectCwes: ['CWE-259']          },
  { path: 'C:/temp/fresh50/python/vuln_weak_md5.py',           expectCwes: ['CWE-328']          },
  { path: 'C:/temp/fresh50/python/vuln_hardcoded_jwt.py',      expectCwes: ['CWE-321']          },
  { path: 'C:/temp/fresh50/python/vuln_weak_des.py',           expectCwes: ['CWE-327']          },
  { path: 'C:/temp/fresh50/python/vuln_multi_sqli_path.py',    expectCwes: ['CWE-89', 'CWE-22'] },
  { path: 'C:/temp/fresh50/python/vuln_multi_cmd_cred.py',     expectCwes: ['CWE-78', 'CWE-259']},
  { path: 'C:/temp/fresh50/python/vuln_multi_sqli_cred.py',    expectCwes: ['CWE-89', 'CWE-259']},
  { path: 'C:/temp/fresh50/python/vuln_sqli_concat.py',        expectCwes: ['CWE-89']           },
  { path: 'C:/temp/fresh50/python/vuln_path_zip.py',           expectCwes: ['CWE-22']           },
  { path: 'C:/temp/fresh50/python/vuln_cmd_env.py',            expectCwes: ['CWE-78']           },
  { path: 'C:/temp/fresh50/python/vuln_hardcoded_fernet.py',   expectCwes: ['CWE-321']          },
  { path: 'C:/temp/fresh50/python/safe_parameterized_sql.py',  expectCwes: []                   },
  { path: 'C:/temp/fresh50/python/safe_path_realpath.py',      expectCwes: []                   },
  { path: 'C:/temp/fresh50/python/safe_subprocess_list.py',    expectCwes: []                   },
  { path: 'C:/temp/fresh50/python/safe_env_secrets.py',        expectCwes: []                   },
  { path: 'C:/temp/fresh50/python/safe_strong_hash.py',        expectCwes: []                   },
  { path: 'C:/temp/fresh50/python/safe_jwt_env_key.py',        expectCwes: []                   },
  // ── Java ────────────────────────────────────────────────────────────────────
  { path: 'C:/temp/fresh50/java/VulnSqlConcat.java',           expectCwes: ['CWE-89']           },
  { path: 'C:/temp/fresh50/java/VulnCmdExec.java',             expectCwes: ['CWE-78']           },
  { path: 'C:/temp/fresh50/java/VulnPathTraversal.java',       expectCwes: ['CWE-22']           },
  { path: 'C:/temp/fresh50/java/VulnHardcodedDbPwd.java',      expectCwes: ['CWE-259']          },
  { path: 'C:/temp/fresh50/java/VulnWeakMD5.java',             expectCwes: ['CWE-328']          },
  { path: 'C:/temp/fresh50/java/VulnHardcodedAES.java',        expectCwes: ['CWE-321']          },
  { path: 'C:/temp/fresh50/java/VulnWeakDES.java',             expectCwes: ['CWE-327']          },
  { path: 'C:/temp/fresh50/java/VulnMultiSqlPath.java',        expectCwes: ['CWE-89', 'CWE-22'] },
  { path: 'C:/temp/fresh50/java/VulnMultiCmdSql.java',         expectCwes: ['CWE-78', 'CWE-89'] },
  { path: 'C:/temp/fresh50/java/VulnMultiCredSql.java',        expectCwes: ['CWE-259', 'CWE-89']},
  { path: 'C:/temp/fresh50/java/VulnRC4.java',                 expectCwes: ['CWE-327']          },
  { path: 'C:/temp/fresh50/java/VulnMultiPathCmd.java',        expectCwes: ['CWE-22', 'CWE-78'] },
  { path: 'C:/temp/fresh50/java/VulnHardcodedToken.java',      expectCwes: ['CWE-321']          },
  { path: 'C:/temp/fresh50/java/SafeParameterizedSql.java',    expectCwes: []                   },
  { path: 'C:/temp/fresh50/java/SafePathCheck.java',           expectCwes: []                   },
  { path: 'C:/temp/fresh50/java/SafeEnvCredential.java',       expectCwes: []                   },
  { path: 'C:/temp/fresh50/java/SafeSecureRandom.java',        expectCwes: []                   },
  { path: 'C:/temp/fresh50/java/SafeListCmd.java',             expectCwes: []                   },
  { path: 'C:/temp/fresh50/java/SafeStrongHash.java',          expectCwes: []                   },
  { path: 'C:/temp/fresh50/java/SafeSha256Hash.java',          expectCwes: []                   },
  // ── C ───────────────────────────────────────────────────────────────────────
  { path: 'C:/temp/fresh50/c/vuln_gets_overflow.c',            expectCwes: ['CWE-787']          },
  { path: 'C:/temp/fresh50/c/vuln_sprintf_overflow.c',         expectCwes: ['CWE-787']          },
  { path: 'C:/temp/fresh50/c/vuln_system_cmd.c',               expectCwes: ['CWE-78']           },
  { path: 'C:/temp/fresh50/c/vuln_hardcoded_cred.c',           expectCwes: ['CWE-259']          },
  { path: 'C:/temp/fresh50/c/vuln_use_after_free.c',           expectCwes: ['CWE-416']          },
  { path: 'C:/temp/fresh50/c/vuln_int_overflow.c',             expectCwes: ['CWE-190']          },
  { path: 'C:/temp/fresh50/c/vuln_multi_bof_cmd.c',            expectCwes: ['CWE-787', 'CWE-78']},
  { path: 'C:/temp/fresh50/c/safe_snprintf_bounds.c',          expectCwes: []                   },
  { path: 'C:/temp/fresh50/c/safe_getenv_cred.c',              expectCwes: []                   },
  { path: 'C:/temp/fresh50/c/safe_free_null.c',                expectCwes: []                   },
];

async function main() {
  await initAstAnalyzer();
  let passed = 0, failed = 0;
  const failures: string[] = [];

  for (const { path: filePath, expectCwes } of TEST_FILES) {
    const code = fs.readFileSync(filePath, 'utf-8');
    const findings = astAnalyzeCode(code, filePath);
    const foundCwes = new Set(findings.map(f => f.cweId));

    let ok: boolean;
    let detail = '';

    if (expectCwes.length === 0) {
      // SAFE: expect zero CWE findings
      ok = foundCwes.size === 0;
      if (!ok) detail = `  FP: found ${[...foundCwes].join(', ')}`;
    } else {
      // VULN: all expected CWEs must be detected
      const missed = expectCwes.filter(c => !foundCwes.has(c));
      ok = missed.length === 0;
      if (!ok) detail = `  FN: missed ${missed.join(', ')}`;
    }

    const label    = ok ? '✓' : '✗';
    const expected = expectCwes.length === 0 ? 'SAFE' : expectCwes.join('+');
    const lang     = filePath.split('/').slice(-2, -1)[0];
    const file     = filePath.split('/').pop()!;
    console.log(`${label}  [${lang}]  ${file.padEnd(38)}  expect: ${expected}`);
    if (!ok) {
      console.log(detail);
      failures.push(`${file} — ${detail.trim()}`);
    }
    ok ? passed++ : failed++;
  }

  console.log(`\n${'─'.repeat(70)}`);
  console.log(`TOTAL: ${passed}/${TEST_FILES.length} passed  |  ${failed} failed`);
  if (failures.length) {
    console.log('\nFailures:');
    failures.forEach(f => console.log('  • ' + f));
  }
}
main().catch(console.error);
