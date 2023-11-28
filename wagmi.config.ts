import { defineConfig } from '@wagmi/cli'
import { foundry } from '@wagmi/cli/plugins'
 
export default defineConfig({
  plugins: [
    foundry({
      artifacts: 'out/',
      
    }),
  ],
  out: './docker/_generated_dhkeabi.ts',
})