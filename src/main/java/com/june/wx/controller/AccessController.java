package com.june.wx.controller;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.apache.commons.codec.digest.DigestUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.ResponseBody;

import com.june.wx.config.WechatConfig;
import com.june.wx.process.WechatProcess;


/**
 * 微信接入，授权
 * 
 * @author wuchaoqun
 *
 */
@Controller
@RequestMapping("/wx/access")
public class AccessController {

	private Logger logger = LoggerFactory.getLogger(AccessController.class);

	@RequestMapping("/test")
	@ResponseBody
	public String hello() {
		return "Hello world!";
	}

	@RequestMapping(value = "/validate", method = RequestMethod.GET)
	public void getWXQRCodeEvent(HttpServletRequest req, HttpServletResponse res) throws IOException {
		if (!checkRequest(req)) {
			logger.info("非微信请求！");
		}
		res.getWriter().print(req.getParameter("echostr"));
		logger.info("成功接入！");
	}
	
	@RequestMapping(value = "/validate", method = RequestMethod.POST)
	public void receiveMessage(HttpServletRequest request, HttpServletResponse response) throws IOException {
		request.setCharacterEncoding("UTF-8");
		response.setCharacterEncoding("UTF-8");
		/** 读取接收到的xml消息 */
		StringBuffer sb = new StringBuffer();
		InputStream is = request.getInputStream();
		InputStreamReader isr = new InputStreamReader(is, "UTF-8");
		BufferedReader br = new BufferedReader(isr);
		String s = "";
		while ((s = br.readLine()) != null) {
			sb.append(s);
		}
		String xml = sb.toString();	//次即为接收到微信端发送过来的xml数据

		String result = "";
		/** 判断是否是微信接入激活验证，只有首次接入验证时才会收到echostr参数，此时需要把它直接返回 */
		String echostr = request.getParameter("echostr");
		if (echostr != null && echostr.length() > 1) {
			result = echostr;
		} else {
			//正常的微信处理流程
			result = new WechatProcess().processWechatMag(xml);
		}

		try {
			OutputStream os = response.getOutputStream();
			os.write(result.getBytes("UTF-8"));
			os.flush();
			os.close();
		} catch (Exception e) {
			e.printStackTrace();
		}
	
	}

	/**
	 * 判断请求是否来自微信
	 */
	private boolean checkRequest(HttpServletRequest req) {
		String token = WechatConfig.TOKEN;
		String signature = req.getParameter("signature");
		String timestamp = req.getParameter("timestamp");
		String nonce = req.getParameter("nonce");
		if (signature != null && timestamp != null && nonce != null) {
			String[] strSet = new String[] { token, timestamp, nonce };
			java.util.Arrays.sort(strSet);
			StringBuffer key = new StringBuffer();
			for (int i = 0; i < strSet.length; i++) {
				key.append(strSet[i]);
			}
			String pwd = DigestUtils.sha1Hex(key.toString());
			return pwd.equals(signature);
		} else {
			return false;
		}
	}
}
