export const toHex = (str: string) =>
  Array.from(new TextEncoder().encode(str))
    .map((b) => b.toString(16).padStart(2, '0'))
    .join('');

export const fromHex = (hex: string) => {
  if (!hex) return '';
  return new TextDecoder().decode(
    Uint8Array.from(hex.match(/.{1,2}/g)!.map((byte) => parseInt(byte, 16)))
  );
};
