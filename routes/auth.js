var express = require('express');
var router = express.Router();
var userModel = require('../schemas/user')
var ResHelper = require('../helper/ResponseHelper');
var userValidator = require('../validators/user');
var { validationResult } = require('express-validator');
var checkLogin = require('../middlewares/checklogin')
var sendmail = require('../helper/sendMail');
const config = require('../configs/config');
const { body } = require('express-validator');
const validator = require('validator');
var bcrypt = require('bcrypt');

router.get('/me', checkLogin, function (req, res, next) {
  ResHelper.RenderRes(res, true, req.user);
});

router.post('/logout', checkLogin, function (req, res, next) {
  if (req.cookies.token) {
    res.status(200)
      .cookie('token', "null", {
        expires: new Date(Date.now + 1000),
        httpOnly: true
      })
      .send({
        success: true,
        data: result.getJWT()
      }
      );
  }
});


router.post('/login', async function (req, res, next) {
  var result = await userModel.GetCre(req.body.username, req.body.password);
  console.log(result);
  if (result.error) {
    ResHelper.RenderRes(res, false, result.error);
  } else {
    res.status(200)
      .cookie('token', result.getJWT(), {
        expires: new Date(Date.now + 24 * 3600 * 1000),
        httpOnly: true
      })
      .send({
        success: true,
        data: result.getJWT()
      }
      );
    //ResHelper.RenderRes(res, true, result.getJWT());

  }
});
router.post('/register', userValidator.checkChain(), async function (req, res, next) {
  var result = validationResult(req);
  if (result.errors.length > 0) {
    ResHelper.RenderRes(res, false, result.errors);
    return;
  }
  try {
    var newUser = new userModel({
      username: req.body.username,
      password: req.body.password,
      email: req.body.email,
      role: ["user"]
    })
    await newUser.save();
    ResHelper.RenderRes(res, true, newUser.getJWT())
  } catch (error) {
    ResHelper.RenderRes(res, false, error)
  }
});


router.post("/forgotPassword",
  body('email').isEmail().withMessage('Email không hợp lệ'),
  async function (req, res, next) {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ errors: errors.array() });
    }
    var user = await userModel.findOne({
      email: req.body.email
    })
    if (user) {
      let token = user.genTokenResetPassword();
      await user.save()
      try {
        let url = `https://${config.hostName}/api/v1/auth/ResetPassword/${token}`;
        let message = `click zo url de reset passs: ${url}`
        sendmail(message, user.email)
        ResHelper.RenderRes(res, true, "Thành công");
      } catch (error) {
        user.resetPasswordToken = undefined;
        user.resetPasswordExp = undefined;
        await user.save();
        ResHelper.RenderRes(res, false, error);
      }
    } else {
      ResHelper.RenderRes(res, false, "Email không tồn tại");
    }
  }
);


router.post("/ResetPassword/:token",
  // Thêm validation cho mật khẩu mới
  body('password').custom(value => {
    if (!validator.isStrongPassword(value)) {
      throw new Error('Mật khẩu mới không đủ mạnh');
    }
    return true;
  }),
  async function (req, res, next) {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ errors: errors.array() });
    }
    var user = await userModel.findOne({
      resetPasswordToken: req.params.token
    })
    if (user) {
      if (user.resetPasswordExp > Date.now()) {
        user.password = req.body.password;
        user.resetPasswordToken = undefined;
        user.resetPasswordExp = undefined;
        await user.save();
        ResHelper.RenderRes(res, true, "Reset thành công");
      } else {
        ResHelper.RenderRes(res, false, "URL hết hạn");
      }
    } else {
      ResHelper.RenderRes(res, false, "URL không hợp lệ");
    }
  }
);


router.post("/ChangePassword", checkLogin,
  // Thêm validation cho mật khẩu mới
  body('password').custom(value => {
    if (!validator.isStrongPassword(value)) {
      throw new Error('Mật khẩu mới không đủ mạnh');
    }
    return true;
  }),
  async function (req, res, next) {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ errors: errors.array() });
    }
    
    if(req.user){
      try {
        const user = await userModel.findById(req.user.id);
        if (!user) {
          return ResHelper.RenderRes(res, false, "Người dùng không tồn tại");
        }
        
        // Kiểm tra xác thực mật khẩu cũ
        const isMatch = await bcrypt.compareSync(req.body.oldPassword, user.password);
        if (!isMatch) {
          return ResHelper.RenderRes(res, false, "Mật khẩu cũ không chính xác");
        }
        
        // Mã hóa và cập nhật mật khẩu mới
        user.password = req.body.password;
        await user.save();
        
        ResHelper.RenderRes(res, true, "Thay đổi mật khẩu thành công");
      } catch (error) {
        ResHelper.RenderRes(res, false, error.message || "Đã xảy ra lỗi khi thay đổi mật khẩu");
      }
    }
  }
);



module.exports = router;