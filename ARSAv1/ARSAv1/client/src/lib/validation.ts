import { z } from 'zod';

export const targetSchema = z.object({
  target: z.string()
    .min(1, "Target is required")
    .refine((value) => {
      // Domain validation
      const domainRegex = /^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$/;
      // IP validation
      const ipRegex = /^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$/;
      
      return domainRegex.test(value) || ipRegex.test(value);
    }, "Please enter a valid domain or IP address"),
  scanType: z.string().min(1, "Scan type is required"),
});

export type TargetInput = z.infer<typeof targetSchema>;

export function validateTarget(target: string): { isValid: boolean; error?: string } {
  try {
    targetSchema.parse({ target, scanType: 'comprehensive' });
    return { isValid: true };
  } catch (error) {
    if (error instanceof z.ZodError) {
      return { isValid: false, error: error.errors[0]?.message || 'Invalid target' };
    }
    return { isValid: false, error: 'Validation failed' };
  }
}
