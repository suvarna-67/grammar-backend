const passport = require("passport");
const GoogleStrategy = require("passport-google-oauth20").Strategy;
const User = require("../models/user");

const normalizeRole = (role) => (role === "recruiter" ? "recruiter" : "jobseeker");

passport.use(
  new GoogleStrategy(
    {
      clientID: process.env.GOOGLE_CLIENT_ID,
      clientSecret: process.env.GOOGLE_CLIENT_SECRET,
      callbackURL:
        process.env.GOOGLE_CALLBACK_URL ||
        "http://localhost:5000/api/auth/google/callback",
      passReqToCallback: true,
    },
    async (req, accessToken, refreshToken, profile, done) => {
      try {
        const email = profile?.emails?.[0]?.value?.toLowerCase();
        if (!email) return done(new Error("Google account email not available"), null);

        const requestedRole = normalizeRole(req.query.state);
        let user = await User.findOne({ email });

        if (!user) {
          user = await User.create({
            name: profile.displayName || email.split("@")[0],
            email,
            googleId: profile.id,
            role: requestedRole,
            employmentStatus: "experienced",
          });
        } else {
          let dirty = false;
          if (!user.googleId) {
            user.googleId = profile.id;
            dirty = true;
          }
          if (!user.role) {
            user.role = requestedRole;
            dirty = true;
          }
          if (dirty) await user.save();
        }

        return done(null, user);
      } catch (err) {
        return done(err, null);
      }
    }
  )
);
