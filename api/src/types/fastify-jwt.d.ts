import "@fastify/jwt";

declare module "@fastify/jwt" {
  interface FastifyJWT {
    user: {
      sub: string;       // userId
      role: string;
      sessionId: string;
      aud?: string | string[];
    };
  }
}
