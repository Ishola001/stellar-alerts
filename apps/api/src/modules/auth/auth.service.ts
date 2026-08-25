import { prisma } from '../../lib/prisma';
import { generateMagicToken, generateSessionToken, verifyToken, MagicLinkPayload } from '../../utils/jwt';
import { redis } from '../../lib/redis';
import jwt from 'jsonwebtoken';

export class AuthService {
  async requestMagicLink(email: string): Promise<string> {
    const token = generateMagicToken(email);
    const decoded = jwt.decode(token) as MagicLinkPayload;
    if (decoded && decoded.jti) {
      await redis.set(`magic_token:${decoded.jti}`, 'valid', 'EX', 15 * 60);
    }
    console.log(`[AuthService] ✉️ Magic link generated: http://localhost:3000/verify?token=${token}`);
    return token;
  }

  async verifyMagicLink(token: string): Promise<{ token: string; user: { id: string; email: string } }> {
    let decoded: MagicLinkPayload;
    try {
      decoded = verifyToken<MagicLinkPayload>(token);
    } catch (err: any) {
      console.error('[AuthService] Token verification failed:', err.message);
      throw new Error('Invalid or expired token');
    }

    if (!decoded || !decoded.email || !decoded.jti) {
      console.error('[AuthService] Token payload missing email or jti:', decoded);
      throw new Error('Invalid or expired token');
    }

    const redisKey = `magic_token:${decoded.jti}`;
    const tokenStatus = await redis.get(redisKey);

    if (!tokenStatus) {
      console.error('[AuthService] Token already used or expired (jti not found in Redis):', decoded.jti);
      throw new Error('Invalid or expired token');
    }

    await redis.del(redisKey);

    try {
      const user = await prisma.user.upsert({
        where: { email: decoded.email },
        update: {},
        create: { email: decoded.email },
      });

      const sessionToken = generateSessionToken({ id: user.id, email: user.email });

      console.log(`[AuthService] Magic link verified for: ${decoded.email}`);
      return { token: sessionToken, user: { id: user.id, email: user.email } };
    } catch (dbError: any) {
      console.error('[AuthService] Database error during magic link verification:', dbError);
      throw dbError;
    }
  }

  async getMe(userId: string) {
    const user = await prisma.user.findUnique({
      where: { id: userId },
      include: {
        wallets: true,
        notifyPrefs: true,
      },
    });

    if (!user) {
      throw new Error('User not found');
    }

    return user;
  }
}

export const authService = new AuthService();
