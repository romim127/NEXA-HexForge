// LAB002-BUG-005: Regression tests for formatActivity() function
// Tests all five analysis states + legacy handling + edge cases
// Run with: node tests/test_format_activity.js

function escapeHtml(text) {
  if (text === null || text === undefined) return '';
  return String(text).replace(/&/g, '&').replace(/</g, '<')
    .replace(/>/g, '>').replace(/"/g, '"').replace(/'/g, '&#039;');
}

// This is a copy of the formatActivity function from hexforge/server/static/app.js
// Kept in sync with the production implementation
function formatActivity(module, data, detailOverrides = {}) {
  const stateLabels = {
    'pending': 'Pendiente',
    'not_applicable': 'No aplicable',
    'no_findings': 'Sin hallazgos',
    'completed': 'Completado',
    'error': 'Error',
  };

  const state = data.state || (data.status === 'no_import_directory' ? 'not_applicable' : 'completed');
  const action = stateLabels[state] || 'Desconocido';

  let detail = '';

  if (state === 'completed') {
    if (detailOverrides.completed) {
      detail = detailOverrides.completed(data);
    }
  } else if (state === 'no_findings') {
    detail = data.reason ? escapeHtml(data.reason) : (detailOverrides.no_findings ? detailOverrides.no_findings(data) : '');
  } else if (state === 'not_applicable') {
    detail = data.reason ? escapeHtml(data.reason) : (detailOverrides.not_applicable ? detailOverrides.not_applicable(data) : '');
  } else if (state === 'error') {
    detail = data.reason ? escapeHtml(data.reason) : 'Error en el análisis';
  }
  // pending: sin detalle adicional

  return { action, detail };
}

let passed = 0;
let failed = 0;

function assert(condition, message) {
  if (condition) {
    console.log(`  ✅ ${message}`);
    passed++;
  } else {
    console.log(`  ❌ ${message}`);
    failed++;
  }
}

console.log('=== LAB002-BUG-005: formatActivity() Regression Tests ===\n');

// Test 1: completed state
const result1 = formatActivity('PE', {
  state: 'completed',
  format: 'PE32+',
  section_count: 18
}, {
  completed: d => `${d.format} • ${d.section_count} secciones`
});
console.log('1. completed state:');
assert(result1.action === 'Completado', 'action should be Completado');
assert(result1.detail === 'PE32+ • 18 secciones', 'detail should match override');
console.log(`   detail: "${result1.detail}"\n`);

// Test 2: no_findings state with reason
const result2 = formatActivity('Imports', {
  state: 'no_findings',
  reason: 'No import directory present'
}, {
  no_findings: d => 'fallback'
});
console.log('2. no_findings (with reason):');
assert(result2.action === 'Sin hallazgos', 'action should be Sin hallazgos');
assert(result2.detail === 'No import directory present', 'detail should be reason');
console.log(`   detail: "${result2.detail}"\n`);

// Test 3: no_findings state without reason (uses override)
const result3 = formatActivity('Strings', {
  state: 'no_findings'
}, {
  no_findings: d => 'fallback detail'
});
console.log('3. no_findings (no reason, with override):');
assert(result3.action === 'Sin hallazgos', 'action should be Sin hallazgos');
assert(result3.detail === 'fallback detail', 'detail should be override');
console.log(`   detail: "${result3.detail}"\n`);

// Test 4: not_applicable state with reason
const result4 = formatActivity('PE', {
  state: 'not_applicable',
  reason: 'Archivo sin estructura PE válida'
}, {
  not_applicable: d => 'fallback'
});
console.log('4. not_applicable (with reason):');
assert(result4.action === 'No aplicable', 'action should be No aplicable');
assert(result4.detail === 'Archivo sin estructura PE válida', 'detail should be reason');
console.log(`   detail: "${result4.detail}"\n`);

// Test 5: not_applicable state without reason (uses override)
const result5 = formatActivity('Indicators', {
  state: 'not_applicable'
}, {
  not_applicable: d => 'Requiere secciones PE analizables'
});
console.log('5. not_applicable (no reason, with override):');
assert(result5.action === 'No aplicable', 'action should be No aplicable');
assert(result5.detail === 'Requiere secciones PE analizables', 'detail should be override');
console.log(`   detail: "${result5.detail}"\n`);

// Test 6: error state with reason
const result6 = formatActivity('Inspector', {
  state: 'error',
  reason: 'Timeout'
});
console.log('6. error (with reason):');
assert(result6.action === 'Error', 'action should be Error');
assert(result6.detail === 'Timeout', 'detail should be reason');
console.log(`   detail: "${result6.detail}"\n`);

// Test 7: error state without reason (default)
const result7 = formatActivity('Registry', {
  state: 'error'
});
console.log('7. error (no reason):');
assert(result7.action === 'Error', 'action should be Error');
assert(result7.detail === 'Error en el análisis', 'detail should be default');
console.log(`   detail: "${result7.detail}"\n`);

// Test 8: pending state (no detail)
const result8 = formatActivity('Timeline (C2)', {
  state: 'pending'
});
console.log('8. pending state:');
assert(result8.action === 'Pendiente', 'action should be Pendiente');
assert(result8.detail === '', 'detail should be empty');
console.log(`   detail: "${result8.detail}"\n`);

// Test 9: legacy imports response (status: no_import_directory)
const result9 = formatActivity('Imports', {
  status: 'no_import_directory'
});
console.log('9. legacy imports (no_import_directory):');
assert(result9.action === 'No aplicable', 'action should be No aplicable');
console.log(`   detail: "${result9.detail}"\n`);

// Test 10: legacy success (no state, no status)
const result10 = formatActivity('Strings', {
  strings: ['hello', 'world']
}, {
  completed: d => `${d.strings.length} cadenas`
});
console.log('10. legacy success (no state):');
assert(result10.action === 'Completado', 'action should be Completado');
assert(result10.detail === '2 cadenas', 'detail should use override');
console.log(`   detail: "${result10.detail}"\n`);

// Test 11: HTML escaping in reason
const result11 = formatActivity('PE', {
  state: 'not_applicable',
  reason: '<script>alert(1)</script> & "quotes"'
});
console.log('11. HTML escaping in reason:');
assert(result11.detail === '<script>alert(1)</script> & "quotes"', 'should escape HTML');
console.log(`   detail: "${result11.detail}"\n`);

// Test 12: null reason handling
const result12 = formatActivity('Test', {
  state: 'not_applicable',
  reason: null
}, {
  not_applicable: () => 'fallback'
});
console.log('12. null reason:');
assert(result12.detail === 'fallback', 'should use override for null reason');
console.log(`   detail: "${result12.detail}"\n`);

// Test 13: undefined reason handling
const result13 = formatActivity('Test', {
  state: 'not_applicable',
  reason: undefined
}, {
  not_applicable: () => 'fallback2'
});
console.log('13. undefined reason:');
assert(result13.detail === 'fallback2', 'should use override for undefined reason');
console.log(`   detail: "${result13.detail}"\n`);

// Test 14: completed with no override (empty detail)
const result14 = formatActivity('Test', {
  state: 'completed'
}, {});
console.log('14. completed with no override:');
assert(result14.action === 'Completado', 'action should be Completado');
assert(result14.detail === '', 'detail should be empty');
console.log(`   detail: "${result14.detail}"\n`);

console.log('=== SUMMARY ===');
console.log(`Passed: ${passed}`);
console.log(`Failed: ${failed}`);
console.log(failed > 0 ? '\n❌ SOME TESTS FAILED' : '\n✅ ALL TESTS PASSED');

process.exit(failed > 0 ? 1 : 0);