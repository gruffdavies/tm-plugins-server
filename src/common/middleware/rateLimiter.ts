import { Request } from 'express';
import { rateLimit } from 'express-rate-limit';

import { env } from '@/common/utils/envConfig';
import { logger } from '@/server';

const rateLimiter = rateLimit({
  legacyHeaders: true,
  limit: env.COMMON_RATE_LIMIT_MAX_REQUESTS ?? 1000, // Increased from 20 to 1000
  message: 'Rate limit exceeded, please try again later.',
  standardHeaders: true,
  windowMs: 60 * 60 * 1000, // Set to 1 hour
  keyGenerator,
});


function keyGenerator(request: Request): string {
  if (!request.ip) {
    logger.warn('Warning: request.ip is missing!');
    return request.socket.remoteAddress as string;
  }

  return request.ip.replace(/:\d+[^:]*$/, '');
}

export default rateLimiter;
