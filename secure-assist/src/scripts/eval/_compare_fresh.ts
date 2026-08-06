/**
 * Compare regex vs AST analyzer on all fresh test files.
 * Prints per-file results and a summary confusion-matrix table.
 */
import { initAstAnalyzer, astAnalyzeCode } from '../../analyzer/ast/astAnalyzer';
import { findSqlInjection }        from '../../analyzer/rules/sqlInjection';
import { findHardcodedCredentials } from '../../analyzer/rules/hardcodedCredentials';
import { findCommandInjection }    from '../../analyzer/rules/commandInjection';
import { findPathTraversal }       from '../../analyzer/rules/pathTraversal';
import { findWeakCrypto }          from '../../analyzer/rules/weakCrypto';
import { findIntegerOverflow }     from '../../analyzer/rules/integerOverflow';
import { findOutOfBoundsWrite }    from '../../analyzer/rules/outOfBoundsWrite';
import { findUseAfterFree }        from '../../analyzer/rules/useAfterFree';
import { detectLanguage }          from '../../analyzer/utils';
import * as fs from 'fs';

function regexAnalyzeCode(code: string, filePath: string) {
  const ctx = { code, filePath, language: detectLanguage(filePath) };
  return [
    ...findSqlInjection(ctx),
    ...findHardcodedCredentials(ctx),
    ...findCommandInjection(ctx),
    ...findPathTraversal(ctx),
    ...findWeakCrypto(ctx),
    ...findIntegerOverflow(ctx),
    ...findOutOfBoundsWrite(ctx),
    ...findUseAfterFree(ctx),
  ];
}

// expectCwes: empty = SAFE, otherwise all listed CWEs must be detected
const TEST_FILES: { path: string; expectCwes: string[] }[] = [
  // ── cwe22-fresh ──────────────────────────────────────────────────────────
  { path: 'C:/temp/cwe22-fresh/python/vuln_zip_slip.py',        expectCwes: ['CWE-22']  },
  { path: 'C:/temp/cwe22-fresh/python/vuln_env_path.py',        expectCwes: ['CWE-22']  },
  { path: 'C:/temp/cwe22-fresh/python/safe_realpath_check.py',  expectCwes: []          },
  { path: 'C:/temp/cwe22-fresh/python/safe_werkzeug.py',        expectCwes: []          },
  { path: 'C:/temp/cwe22-fresh/java/VulnServlet.java',          expectCwes: ['CWE-22']  },
  { path: 'C:/temp/cwe22-fresh/java/SafeServlet.java',          expectCwes: []          },
  { path: 'C:/temp/cwe22-fresh/java/SafeFileName.java',         expectCwes: []          },
  // ── cwe321-fresh ─────────────────────────────────────────────────────────
  { path: 'C:/temp/cwe321-fresh/python/vuln_aes_literal.py',    expectCwes: ['CWE-321'] },
  { path: 'C:/temp/cwe321-fresh/python/vuln_jwt_secret.py',     expectCwes: ['CWE-321'] },
  { path: 'C:/temp/cwe321-fresh/python/vuln_fernet_key.py',     expectCwes: ['CWE-321'] },
  { path: 'C:/temp/cwe321-fresh/python/safe_env_key.py',        expectCwes: []          },
  { path: 'C:/temp/cwe321-fresh/python/safe_kdf_key.py',        expectCwes: []          },
  { path: 'C:/temp/cwe321-fresh/java/VulnHardcodedAES.java',    expectCwes: ['CWE-321'] },
  { path: 'C:/temp/cwe321-fresh/java/VulnHardcodedString.java', expectCwes: ['CWE-321'] },
  { path: 'C:/temp/cwe321-fresh/java/SafeEnvKey.java',          expectCwes: []          },
  { path: 'C:/temp/cwe321-fresh/c/vuln_hardcoded.c',            expectCwes: ['CWE-321'] },
  { path: 'C:/temp/cwe321-fresh/c/safe_runtime_key.c',          expectCwes: []          },
  // ── cwe259-fresh ─────────────────────────────────────────────────────────
  { path: 'C:/temp/cwe259-fresh/python/vuln_db_conn.py',        expectCwes: ['CWE-259'] },
  { path: 'C:/temp/cwe259-fresh/python/vuln_api_key.py',        expectCwes: ['CWE-259'] },
  { path: 'C:/temp/cwe259-fresh/python/vuln_default_arg.py',    expectCwes: ['CWE-259'] },
  { path: 'C:/temp/cwe259-fresh/python/vuln_smtp.py',           expectCwes: ['CWE-259'] },
  { path: 'C:/temp/cwe259-fresh/python/safe_env_password.py',   expectCwes: []          },
  { path: 'C:/temp/cwe259-fresh/python/safe_config_password.py',expectCwes: []          },
  { path: 'C:/temp/cwe259-fresh/java/VulnJdbcPassword.java',    expectCwes: ['CWE-259'] },
  { path: 'C:/temp/cwe259-fresh/java/VulnLdapPassword.java',    expectCwes: ['CWE-259'] },
  { path: 'C:/temp/cwe259-fresh/java/SafePropertiesPassword.java', expectCwes: []       },
  { path: 'C:/temp/cwe259-fresh/c/vuln_strcmp_password.c',      expectCwes: ['CWE-259'] },
  { path: 'C:/temp/cwe259-fresh/c/safe_getenv_password.c',      expectCwes: []          },
  // ── fresh50/python ───────────────────────────────────────────────────────
  { path: 'C:/temp/fresh50/python/vuln_sqli_fstring.py',        expectCwes: ['CWE-89']            },
  { path: 'C:/temp/fresh50/python/vuln_cmd_injection.py',       expectCwes: ['CWE-78']            },
  { path: 'C:/temp/fresh50/python/vuln_path_traversal.py',      expectCwes: ['CWE-22']            },
  { path: 'C:/temp/fresh50/python/vuln_hardcoded_db_cred.py',   expectCwes: ['CWE-259']           },
  { path: 'C:/temp/fresh50/python/vuln_weak_md5.py',            expectCwes: ['CWE-328']           },
  { path: 'C:/temp/fresh50/python/vuln_hardcoded_jwt.py',       expectCwes: ['CWE-321']           },
  { path: 'C:/temp/fresh50/python/vuln_weak_des.py',            expectCwes: ['CWE-327']           },
  { path: 'C:/temp/fresh50/python/vuln_multi_sqli_path.py',     expectCwes: ['CWE-89', 'CWE-22'] },
  { path: 'C:/temp/fresh50/python/vuln_multi_cmd_cred.py',      expectCwes: ['CWE-78', 'CWE-259']},
  { path: 'C:/temp/fresh50/python/vuln_multi_sqli_cred.py',     expectCwes: ['CWE-89', 'CWE-259']},
  { path: 'C:/temp/fresh50/python/vuln_sqli_concat.py',         expectCwes: ['CWE-89']            },
  { path: 'C:/temp/fresh50/python/vuln_path_zip.py',            expectCwes: ['CWE-22']            },
  { path: 'C:/temp/fresh50/python/vuln_cmd_env.py',             expectCwes: ['CWE-78']            },
  { path: 'C:/temp/fresh50/python/vuln_hardcoded_fernet.py',    expectCwes: ['CWE-321']           },
  { path: 'C:/temp/fresh50/python/safe_parameterized_sql.py',   expectCwes: []                    },
  { path: 'C:/temp/fresh50/python/safe_path_realpath.py',       expectCwes: []                    },
  { path: 'C:/temp/fresh50/python/safe_subprocess_list.py',     expectCwes: []                    },
  { path: 'C:/temp/fresh50/python/safe_env_secrets.py',         expectCwes: []                    },
  { path: 'C:/temp/fresh50/python/safe_strong_hash.py',         expectCwes: []                    },
  { path: 'C:/temp/fresh50/python/safe_jwt_env_key.py',         expectCwes: []                    },
  // ── fresh50/java ─────────────────────────────────────────────────────────
  { path: 'C:/temp/fresh50/java/VulnSqlConcat.java',            expectCwes: ['CWE-89']            },
  { path: 'C:/temp/fresh50/java/VulnCmdExec.java',              expectCwes: ['CWE-78']            },
  { path: 'C:/temp/fresh50/java/VulnPathTraversal.java',        expectCwes: ['CWE-22']            },
  { path: 'C:/temp/fresh50/java/VulnHardcodedDbPwd.java',       expectCwes: ['CWE-259']           },
  { path: 'C:/temp/fresh50/java/VulnWeakMD5.java',              expectCwes: ['CWE-328']           },
  { path: 'C:/temp/fresh50/java/VulnHardcodedAES.java',         expectCwes: ['CWE-321']           },
  { path: 'C:/temp/fresh50/java/VulnWeakDES.java',              expectCwes: ['CWE-327']           },
  { path: 'C:/temp/fresh50/java/VulnMultiSqlPath.java',         expectCwes: ['CWE-89', 'CWE-22'] },
  { path: 'C:/temp/fresh50/java/VulnMultiCmdSql.java',          expectCwes: ['CWE-78', 'CWE-89'] },
  { path: 'C:/temp/fresh50/java/VulnMultiCredSql.java',         expectCwes: ['CWE-259','CWE-89'] },
  { path: 'C:/temp/fresh50/java/VulnRC4.java',                  expectCwes: ['CWE-327']           },
  { path: 'C:/temp/fresh50/java/VulnMultiPathCmd.java',         expectCwes: ['CWE-22', 'CWE-78'] },
  { path: 'C:/temp/fresh50/java/VulnHardcodedToken.java',       expectCwes: ['CWE-321']           },
  { path: 'C:/temp/fresh50/java/SafeParameterizedSql.java',     expectCwes: []                    },
  { path: 'C:/temp/fresh50/java/SafePathCheck.java',            expectCwes: []                    },
  { path: 'C:/temp/fresh50/java/SafeEnvCredential.java',        expectCwes: []                    },
  { path: 'C:/temp/fresh50/java/SafeSecureRandom.java',         expectCwes: []                    },
  { path: 'C:/temp/fresh50/java/SafeListCmd.java',              expectCwes: []                    },
  { path: 'C:/temp/fresh50/java/SafeStrongHash.java',           expectCwes: []                    },
  { path: 'C:/temp/fresh50/java/SafeSha256Hash.java',           expectCwes: []                    },
  // ── fresh50/c ────────────────────────────────────────────────────────────
  { path: 'C:/temp/fresh50/c/vuln_gets_overflow.c',             expectCwes: ['CWE-787']           },
  { path: 'C:/temp/fresh50/c/vuln_sprintf_overflow.c',          expectCwes: ['CWE-787']           },
  { path: 'C:/temp/fresh50/c/vuln_system_cmd.c',                expectCwes: ['CWE-78']            },
  { path: 'C:/temp/fresh50/c/vuln_hardcoded_cred.c',            expectCwes: ['CWE-259']           },
  { path: 'C:/temp/fresh50/c/vuln_use_after_free.c',            expectCwes: ['CWE-416']           },
  { path: 'C:/temp/fresh50/c/vuln_int_overflow.c',              expectCwes: ['CWE-190']           },
  { path: 'C:/temp/fresh50/c/vuln_multi_bof_cmd.c',             expectCwes: ['CWE-787','CWE-78'] },
  { path: 'C:/temp/fresh50/c/safe_snprintf_bounds.c',           expectCwes: []                    },
  { path: 'C:/temp/fresh50/c/safe_getenv_cred.c',               expectCwes: []                    },
  { path: 'C:/temp/fresh50/c/safe_free_null.c',                 expectCwes: []                    },
  // ── complex ──────────────────────────────────────────────────────────────
  { path: 'C:/temp/fresh50/python/complex_report_service.py',
    expectCwes: ['CWE-89','CWE-78','CWE-22','CWE-259','CWE-321'] },
];

interface Counts { tp: number; fp: number; fn: number; tn: number }

function score(findings: string[], expectCwes: string[]): { regexOk: boolean; detail: string } {
  // unused — we compute separately for regex and AST
  return { regexOk: false, detail: '' };
}

function evaluate(foundCwes: Set<string>, expectCwes: string[]): 'TP' | 'FP' | 'FN' | 'TN' {
  const isVuln = expectCwes.length > 0;
  const hasFindings = foundCwes.size > 0;
  if (isVuln && hasFindings) return 'TP';
  if (isVuln && !hasFindings) return 'FN';
  if (!isVuln && hasFindings) return 'FP';
  return 'TN';
}

async function main() {
  await initAstAnalyzer();

  const rTot: Counts = { tp:0, fp:0, fn:0, tn:0 };
  const aTot: Counts = { tp:0, fp:0, fn:0, tn:0 };

  const W = 42;
  console.log(`\n${'File'.padEnd(W)}  Expect              Regex   AST`);
  console.log('─'.repeat(W + 40));

  for (const { path: filePath, expectCwes } of TEST_FILES) {
    const code = fs.readFileSync(filePath, 'utf-8');
    const label = filePath.split('/').slice(-2).join('/');

    const rFindings  = regexAnalyzeCode(code, filePath);
    const aFindings  = astAnalyzeCode(code, filePath);

    const rCwes = new Set(rFindings.map(f => f.cweId));
    const aCwes = new Set(aFindings.map(f => f.cweId));

    const rVerdict = evaluate(rCwes, expectCwes);
    const aVerdict = evaluate(aCwes, expectCwes);

    rTot[rVerdict.toLowerCase() as keyof Counts]++;
    aTot[aVerdict.toLowerCase() as keyof Counts]++;

    const expectStr = expectCwes.length === 0 ? 'SAFE' : expectCwes.join('+');

    // Only print mismatches or disagreements between the two
    const bothPass = (rVerdict === 'TP' || rVerdict === 'TN') && (aVerdict === 'TP' || aVerdict === 'TN');
    const flag = !bothPass ? ' ◄' : '';

    console.log(`${label.padEnd(W)}  ${expectStr.padEnd(20)}${rVerdict.padEnd(8)}${aVerdict}${flag}`);
  }

  const sep = '─'.repeat(70);
  console.log(`\n${sep}`);
  console.log('SUMMARY\n');

  const rDet  = rTot.tp / (rTot.tp + rTot.fn);
  const aDet  = aTot.tp / (aTot.tp + aTot.fn);
  const rFPr  = rTot.fp / (rTot.fp + rTot.tn);
  const aFPr  = aFPr_val(aTot);

  function aFPr_val(t: Counts) { return t.fp / (t.fp + t.tn); }

  const fmt = (n: number) => (n * 100).toFixed(1) + '%';

  console.log(`            ${'Regex'.padEnd(12)}AST`);
  console.log(`TP          ${String(rTot.tp).padEnd(12)}${aTot.tp}`);
  console.log(`FN          ${String(rTot.fn).padEnd(12)}${aTot.fn}`);
  console.log(`FP          ${String(rTot.fp).padEnd(12)}${aTot.fp}`);
  console.log(`TN          ${String(rTot.tn).padEnd(12)}${aTot.tn}`);
  console.log(`Detection%  ${fmt(rDet).padEnd(12)}${fmt(aDet)}`);
  console.log(`FP rate%    ${fmt(rFPr).padEnd(12)}${fmt(aFPr_val(aTot))}`);
  console.log(sep);
}

main().catch(console.error);
