export function splitSeed(seed: string, threshold: number, count: number, passphrase: string): Promise<string[]>;
export function recoverSeed(shares: string[], passphrase: string): Promise<string>;
export function normalizeBip39(seed: string): string;
export function checkBip39(seed: string): {ok: true; words: number} | {ok: false; error: string};
export function sampleSeed(): string;
export function parseShares(text: string): string[];
export function qrSvg(text: string, dark?: string, light?: string): string;
