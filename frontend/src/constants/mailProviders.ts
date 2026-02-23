export const mailProviderOptions = [
  { label: 'Moemail', value: 'moemail' },
  { label: 'DuckMail', value: 'duckmail' },
  { label: 'Freemail', value: 'freemail' },
  { label: 'GPTMail', value: 'gptmail' },
  { label: 'CF Worker', value: 'cfworker' },
] as const

export type TempMailProvider = typeof mailProviderOptions[number]['value']

export const defaultMailProvider: TempMailProvider = 'moemail'
