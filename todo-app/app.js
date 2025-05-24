const express = require("express");
var csrf = require("tiny-csrf");
const app = express();
const bodyParser = require("body-parser");
var cookieParser = require("cookie-parser");
const path = require("path");
const passport = require("passport");
const connectEnsureLogin = require("connect-ensure-login");
const session = require("express-session");
const LocalStrategy = require("passport-local");
const flash = require("connect-flash");
const bcrypt = require("bcrypt");

const saltRounds = 10;
app.set("views", path.join(__dirname, "views"));
app.set("view engine", "ejs");

app.use(flash());
app.use(express.static(path.join(__dirname, "public")));
app.use(bodyParser.json());
app.use(express.urlencoded({ extended: false }));
app.use(cookieParser("shh! some secrete string"));
app.use(csrf("this_should_be_32_character_long", ["POST", "PUT", "DELETE"]));
app.use(
  session({
    secret: "my-super-secret-key-21728172615261562",
    cookie: { maxAge: 24 * 60 * 60 * 1000 },
  })
);
app.use(passport.initialize());
app.use(passport.session());

app.use((req, res, next) => {
  res.locals.messages = req.flash();
  next();
});

const { Todo, User } = require("./models");

passport.use(
  new LocalStrategy(
    { usernameField: "email", passwordField: "password" },
    async (username, password, done) => {
      try {
        const user = await User.findOne({ where: { email: username } });
        if (!user) {
          return done(null, false, {
            message: "Account doesn't exist for this mail",
          });
        }
        const match = await bcrypt.compare(password, user.password);
        if (match) {
          return done(null, user);
        } else {
          return done(null, false, { message: "Invalid password" });
        }
      } catch (err) {
        return done(err);
      }
    }
  )
);

passport.serializeUser((user, done) => {
  done(null, user.id);
});
passport.deserializeUser((id, done) => {
  User.findByPk(id)
    .then((user) => done(null, user))
    .catch((err) => done(err));
});

app.get("/", async (req, res) => {
  if (req.isAuthenticated()) {
    return res.redirect("/todos");
  }
  return res.render("index", {
    title: "Todo Application",
    csrfToken: req.csrfToken(),
  });
});

app.get("/signup", (req, res) => {
  res.render("signup", {
    title: "Signup",
    csrfToken: req.csrfToken(),
  });
});

app.post("/users", async (req, res, next) => {
  const { email, firstName, password, lastName } = req.body;
  if (!email) {
    req.flash("error", "Email can not be empty!");
    return res.redirect("/signup");
  }
  if (!firstName) {
    req.flash("error", "First name can not be empty!");
    return res.redirect("/signup");
  }
  if (!password || password.length < 8) {
    req.flash("error", "Password length should be minimum 8");
    return res.redirect("/signup");
  }

  try {
    const hashedPwd = await bcrypt.hash(password, saltRounds);
    const user = await User.create({
      firstName,
      lastName,
      email,
      password: hashedPwd,
    });
    req.login(user, (err) => {
      if (err) {
        console.log(err);
        return next(err);
      }
      return res.redirect("/todos");
    });
  } catch (err) {
    console.log(err);
    return res.redirect("/signup");
  }
});

app.get("/login", (req, res) => {
  res.render("login", {
    title: "Login",
    csrfToken: req.csrfToken(),
  });
});

app.post(
  "/session",
  passport.authenticate("local", {
    failureRedirect: "/login",
    failureFlash: true,
  }),
  (req, res) => {
    res.redirect("/todos");
  }
);

app.get("/signout", (req, res, next) => {
  req.logout((err) => {
    if (err) return next(err);
    res.redirect("/");
  });
});

app.get("/todos", connectEnsureLogin.ensureLoggedIn(), async (req, res) => {
  try {
    const loggedInUser = req.user.id;
    const allTodos = await Todo.findAll({ where: { userId: loggedInUser } });
    const overdue = await Todo.overdue(loggedInUser);
    const dueLater = await Todo.dueLater(loggedInUser);
    const dueToday = await Todo.dueToday(loggedInUser);
    const completedItems = await Todo.completedItems(loggedInUser);

    if (req.accepts("html")) {
      return res.render("todo", {
        title: "Todo Application",
        allTodos,
        overdue,
        dueToday,
        dueLater,
        completedItems,
        csrfToken: req.csrfToken(),
      });
    } else {
      return res.json(allTodos);
    }
  } catch (err) {
    console.log(err);
    return res.status(422).json(err);
  }
});

app.get("/todos/:id", connectEnsureLogin.ensureLoggedIn(), async (req, res) => {
  try {
    const todo = await Todo.findOne({
      where: {
        id: req.params.id,
        userId: req.user.id,
      },
    });
    if (todo) return res.json(todo);
    else return res.status(404).json({ error: "Todo not found" });
  } catch (err) {
    console.log(err);
    return res.status(422).json(err);
  }
});

app.post("/todos", connectEnsureLogin.ensureLoggedIn(), async (req, res) => {
  const { title, dueDate } = req.body;
  if (!title) {
    req.flash("error", "Title can not be empty!");
    return res.redirect("/todos");
  }
  if (!dueDate) {
    req.flash("error", "Due date can not be empty!");
    return res.redirect("/todos");
  }

  try {
    await Todo.addTodo({
      title,
      dueDate,
      completed: false,
      userId: req.user.id,
    });
    return res.redirect("/todos");
  } catch (err) {
    console.log(err);
    return res.status(422).json(err);
  }
});

app.put("/todos/:id", connectEnsureLogin.ensureLoggedIn(), async (req, res) => {
  try {
    const todo = await Todo.findOne({
      where: {
        id: req.params.id,
        userId: req.user.id,
      },
    });
    if (!todo) return res.status(404).json({ error: "Todo not found" });

    const updatedTodo = await todo.setCompletionStatus(req.body.completed);
    return res.json(updatedTodo);
  } catch (err) {
    console.log(err);
    return res.status(422).json(err);
  }
});

app.delete("/todos/:id", connectEnsureLogin.ensureLoggedIn(), async (req, res) => {
  try {
    const rowsDeleted = await Todo.remove(req.params.id, req.user.id);
    return res.json({ success: rowsDeleted > 0 });
  } catch (err) {
    console.log(err);
    return res.status(422).json(err);
  }
});

module.exports = app;

