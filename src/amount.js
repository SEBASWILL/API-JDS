/**
 * Convierte textos de monto en número. Soporta "$25.000,00", "COP 25,000.00",
 * "25.000", "12,50", 25000. Regla: un único separador seguido de exactamente
 * 3 dígitos se interpreta como miles (25.000 = veinticinco mil), pensado para COP.
 */
export function parseAmount(input) {
  if (typeof input === 'number') {
    return Number.isFinite(input) && input > 0 ? Math.round(input * 100) / 100 : null;
  }
  if (typeof input !== 'string') return null;

  let s = input.replace(/[^\d.,]/g, '');
  if (!/\d/.test(s)) return null;

  const lastDot = s.lastIndexOf('.');
  const lastComma = s.lastIndexOf(',');
  let dec = null;

  if (lastDot > -1 && lastComma > -1) {
    dec = lastDot > lastComma ? '.' : ',';
  } else {
    const sep = lastDot > -1 ? '.' : lastComma > -1 ? ',' : null;
    if (sep) {
      const count = s.split(sep).length - 1;
      const after = s.length - s.lastIndexOf(sep) - 1;
      if (count === 1 && after !== 3) dec = sep;
    }
  }

  if (dec) {
    const i = s.lastIndexOf(dec);
    s = s.slice(0, i).replace(/[.,]/g, '') + '.' + s.slice(i + 1);
  } else {
    s = s.replace(/[.,]/g, '');
  }
  const n = Number(s);
  return Number.isFinite(n) && n > 0 ? Math.round(n * 100) / 100 : null;
}
