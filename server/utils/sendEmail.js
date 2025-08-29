const nodemailer = require("nodemailer");

const transporter = nodemailer.createTransport({
  host: process.env.MAIL_HOST,
  port: Number(process.env.MAIL_PORT),
  auth: { user: process.env.MAIL_USER, pass: process.env.MAIL_PASS },
});

module.exports = async function sendEmail(to, subject, html) {
  await transporter.sendMail({
    from: process.env.EMAIL_FROM,
    to, subject, html,
  });
};
