import type { FastifyPluginAsync } from "fastify";
import {
  registerSchema,
  loginSchema,
  refreshSchema,
  logoutSchema,
  verifyEmailSchema,
  forgotPasswordSchema,
  resetPasswordSchema,
} from "./auth.schemas";
import {
  accessTokenTtlSeconds,
  createUserAndSession,
  introspectToken,
  loginAndCreateSession,
  logoutSession,
  refreshSession,
  verifyEmail,
  requestPasswordReset,
  resetPassword,
} from "./auth.service";
import { introspectSchema } from "./auth.schemas";

const isTest = process.env.NODE_ENV === "test";

const rl = (cfg: object) => (isTest ? {} : { config: { rateLimit: cfg } });

export const authRoutes: FastifyPluginAsync = async (app) => {
  const issueAccessToken = (userId: string, role: string, sessionId: string) =>
    app.jwt.sign({ role, sessionId }, { sub: userId, expiresIn: accessTokenTtlSeconds() });

  app.post("/auth/register", rl({ max: 5, timeWindow: "1 minute" }), async (req, reply) => {
    const body = registerSchema.parse(req.body);
    const tokens = await createUserAndSession({
      email: body.email.toLowerCase(),
      password: body.password,
      displayName: body.displayName,
      issueAccessToken,
    });
    req.log.info({ email: body.email.toLowerCase() }, "auth.register");
    return reply.code(201).send(tokens);
  });

  app.post("/auth/login", rl({ max: 10, timeWindow: "1 minute" }), async (req, reply) => {
    const body = loginSchema.parse(req.body);
    try {
      const result = await loginAndCreateSession({
        email: body.email.toLowerCase(),
        password: body.password,
        userAgent: req.headers["user-agent"],
        ipAddress: req.ip,
        issueAccessToken,
      });
      const { userId, ...tokens } = result;
      req.log.info({ userId }, "auth.login");
      return reply.send(tokens);
    } catch (err: any) {
      if (err?.statusCode === 401) {
        req.log.warn({ email: body.email.toLowerCase(), ip: req.ip }, "auth.login_failed");
      }
      throw err;
    }
  });

  app.post("/auth/refresh", rl({ max: 30, timeWindow: "1 minute" }), async (req, reply) => {
    const body = refreshSchema.parse(req.body);
    const tokens = await refreshSession({ refreshToken: body.refreshToken, issueAccessToken });
    return reply.send(tokens);
  });

  app.post("/auth/logout", async (req, reply) => {
    const body = logoutSchema.parse(req.body);
    await logoutSession(body.refreshToken);
    return reply.code(204).send();
  });

  app.post("/auth/verify-email", async (req, reply) => {
    const { token } = verifyEmailSchema.parse(req.body);
    const { userId } = await verifyEmail(token);
    req.log.info({ userId }, "auth.email_verified");
    return reply.send({ message: "Email verified" });
  });

  app.post("/auth/forgot-password", rl({ max: 5, timeWindow: "15 minutes" }), async (req, reply) => {
    const { email } = forgotPasswordSchema.parse(req.body);
    await requestPasswordReset(email);
    return reply.send({ message: "If that email is registered you will receive a reset link" });
  });

  app.post("/auth/reset-password", rl({ max: 10, timeWindow: "15 minutes" }), async (req, reply) => {
    const { token, password } = resetPasswordSchema.parse(req.body);
    await resetPassword(token, password);
    return reply.send({ message: "Password updated" });
  });

  app.post("/auth/introspect", rl({ max: 30, timeWindow: "1 minute" }), async (req, reply) => {
    const { token } = introspectSchema.parse(req.body);
    const result = await introspectToken(token, (t) => app.jwt.verify(t));
    return reply.send(result);
  });
};
