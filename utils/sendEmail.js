const nodemailer = require("nodemailer");
const { google } = require("googleapis");

const oAuth2Client = new google.auth.OAuth2(
    process.env.EMAIL_CLIENT_ID,
    process.env.EMAIL_CLIENT_SECRET,
    "https://developers.google.com/oauthplayground"
);

oAuth2Client.setCredentials({
    refresh_token: process.env.EMAIL_REFRESH_TOKEN,
});

const sendEmail = async (to, otp, context = "password_reset") => {
    try {
        const accessToken = await oAuth2Client.getAccessToken();

        const transporter = nodemailer.createTransport({
            service: "gmail",
            auth: {
                type: "OAuth2",
                user: process.env.EMAIL_USER,
                clientId: process.env.EMAIL_CLIENT_ID,
                clientSecret: process.env.EMAIL_CLIENT_SECRET,
                refreshToken: process.env.EMAIL_REFRESH_TOKEN,
                accessToken: accessToken && accessToken.token ? accessToken.token : accessToken,
            },
        });

        const isSignin = context === "signin";
        const subject = isSignin
            ? "RhirePro - OTP for Sign In Verification"
            : "RhirePro - OTP for Password Reset";
        const heading = isSignin
            ? "RhirePro Sign In Verification"
            : "RhirePro Password Reset";
        const intro = isSignin
            ? "Use this OTP to complete your sign in:"
            : "Your OTP is:";

        const info = await transporter.sendMail({
            from: `"RhirePro Support" <${process.env.EMAIL_USER}>`,
            to,
            subject,
            html: `
                <div style="font-family:Arial;padding:20px">
                    <h2>${heading}</h2>
                    <p>${intro}</p>
                    <h1 style="letter-spacing:5px">${otp}</h1>
                    <p>This OTP expires in 5 minutes.</p>
                </div>
            `,
        });

        console.log("✅ OTP Email Sent:", info.messageId);
        return true;
    } catch (error) {
        console.error("❌ Email sending failed:", error);
        return false;
    }
};

module.exports = sendEmail;
