import nodemailer from "nodemailer";

let _transport: nodemailer.Transporter | null = null;

function getTransport(): nodemailer.Transporter {
  if (!_transport) {
    _transport = nodemailer.createTransport({
      host: process.env.SMTP_HOST!,
      port: Number(process.env.SMTP_PORT ?? 587),
      secure: process.env.SMTP_SECURE === "true",
      auth: {
        user: process.env.SMTP_USER!,
        pass: process.env.SMTP_PASS!,
      },
    });
  }
  return _transport;
}

const FROM = process.env.SMTP_FROM ?? "no-reply@example.com";

export async function sendVerificationEmail(to: string, token: string): Promise<void> {
  const url = `${process.env.APP_URL}/verify-email?token=${token}`;
  await getTransport().sendMail({
    from: FROM,
    to,
    subject: "Verify your email address",
    text: `Click the link below to verify your email address. It expires in 24 hours.\n\n${url}`,
    html: `<p>Click the link below to verify your email address. It expires in 24 hours.</p><p><a href="${url}">${url}</a></p>`,
  });
}

export async function sendPasswordResetEmail(to: string, token: string): Promise<void> {
  const url = `${process.env.APP_URL}/reset-password?token=${token}`;
  await getTransport().sendMail({
    from: FROM,
    to,
    subject: "Reset your password",
    text: `Click the link below to reset your password. It expires in 1 hour.\n\n${url}`,
    html: `<p>Click the link below to reset your password. It expires in 1 hour.</p><p><a href="${url}">${url}</a></p>`,
  });
}
