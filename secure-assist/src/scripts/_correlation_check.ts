import { correlateFindings } from '../model/correlation';

const F = (cweId: string, line: number): any => ({ cweId, line, ruleId: '', message: '' });
const M = (cwe: string, start?: number): any => ({ cwe, start_line: start, end_line: start, fixes: [] });

function show(name: string, statics: any[], models: any[]) {
  const r = correlateFindings(statics, models);
  console.log(`\n=== ${name} ===`);
  console.log(`  confirmed static: [${[...r.confirmedStatic].join(', ')}] of ${statics.length}`);
  console.log(`  confirmed model : [${[...r.confirmedModel].join(', ')}] of ${models.length}`);
  r.intersections.forEach(i =>
    console.log(`    static#${i.staticIndex} <-> model#${i.modelIndex}  ${i.reason}`)
  );
}

// The FileService.java case: analyzer flags the sinks, model flags the builder.
show('different locations, same CWE',
  [F('CWE-22', 23), F('CWE-22', 24)],
  [M('CWE-22', 18)]);

// Exact match should still win and be labelled as an overlapping line.
show('same line',
  [F('CWE-89', 19)],
  [M('CWE-89', 19)]);

// One model finding must not claim three static findings.
show('1 model vs 3 static (no over-matching)',
  [F('CWE-89', 10), F('CWE-89', 20), F('CWE-89', 30)],
  [M('CWE-89', 99)]);

// Different CWEs must never pair.
show('different CWEs',
  [F('CWE-89', 10)],
  [M('CWE-78', 10)]);
