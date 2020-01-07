<?php
/**
 * Created by PhpStorm
 * PROJECT:微信相关包
 * User: sunny
 * Desc:获取微信相关权限:access_token签名等
 */

namespace wechat\auth;

use think\Cache;
use wechat\config\WechatConfig;
use wechat\config\Common;

class WxConfig {
    private $appid;
    private $appSecret;
    /*
     * 储存微信token的表
     * CREATE TABLE `wechat_token` (
      `id` int(11) NOT NULL AUTO_INCREMENT,
      `access_token` varchar(255) NOT NULL DEFAULT '',
      `access_token_expire_time` int(10) NOT NULL DEFAULT '0',
      `jsapi_ticket` varchar(255) DEFAULT NULL,
      `jsapi_ticket_expire_time` int(10) NOT NULL DEFAULT '0',
      PRIMARY KEY (`id`)
    ) ENGINE=MyISAM AUTO_INCREMENT=3 DEFAULT CHARSET=utf8mb4 COMMENT='微信的token';
     */
    private $wechatData;

    public function __construct($appId, $appSecret) {
        $this->appid = WechatConfig::APPID;
        $this->appSecret = WechatConfig::APPSECRET;
        $this->wechatData = db("wechat_token")->where("id",1)->find();
        if(!$this->wechatData){
            //初始化
            db("wechat_token")->insert(['id'=>1]);
        }
    }

    public function getSignPackage($url = NULL) {
        $jsapiTicket = $this->getJsApiTicket();

        if($jsapiTicket === false){
            return false;
        }

        if(!$url){
            $protocol = (!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off' || $_SERVER['SERVER_PORT'] == 443) ? "https://" : "http://";
            $url = "$protocol$_SERVER[HTTP_HOST]$_SERVER[REQUEST_URI]";
        }

        $timestamp = time();
        $nonceStr = Common::createNonceStr();

        // 这里参数的顺序要按照 key 值 ASCII 码升序排序
        $string = "jsapi_ticket=$jsapiTicket&noncestr=$nonceStr&timestamp=$timestamp&url=$url";

        $signature = sha1($string);
        $signPackage = array(
            "appId"     => $this->appid,
            "nonceStr"  => $nonceStr,
            "timestamp" => $timestamp,
            "url"       =>$url,
            "signature" => $signature,
            "rawString" => $string
        );
        return $signPackage;
    }



    public function getJsApiTicket($reset=false) {
        // jsapi_ticket 应该全局存储与更新，以下代码以写入到文件中做示例
        $data = $this->wechatData;
        if (!$data || $data['jsapi_ticket_expire_time'] < time()) {
            $accessToken = $this->getAccessToken($reset);
            if($accessToken === false){
                return false;
            }
            // 如果是企业号用以下 URL 获取 ticket
            $url = sprintf(WechatConfig::GET_JSAPI_TICKET_URL, $accessToken);
            $res = json_decode(Common::postCurl($url, 'GET'), true);
            if(json_encode($res) != "null"  && array_key_exists("ticket",$res) && $res['ticket']){
                $ticket = $res['ticket'];
            }else{
                if(strpos($res['errmsg'],"invalid credential, access_token is invalid or not latest hints") === 0){
                    $this->getJsApiTicket(true);
                }
                return false;
            }
            if ($ticket) {
                $data['jsapi_ticket_expire_time'] = time() + (int)WechatConfig::EXPIRE_ACCESS_TOKEN;
                $data['jsapi_ticket'] = $ticket;
                db("wechat_token")->where("id",1)->update($data);
            }
        } else {
            $ticket = $data['jsapi_ticket'];
        }

        return $ticket;
    }

    public function getAccessToken($reset=false) {
        // access_token 应该全局存储与更新，以下代码以写入到文件中做示例
        $data = $this->wechatData;
        if (!$data || $data['access_token_expire_time'] < time() || $reset) {
            // 如果是企业号用以下URL获取access_token
            $url = sprintf(WechatConfig::GET_ACCESS_TOKEN_URL, $this->appid, $this->appSecret);
            $res = json_decode(Common::postCurl($url, 'GET'), true);
            if(json_encode($res) != "null" && array_key_exists("access_token",$res) && $res['access_token']){
                $access_token = $res['access_token'];
            }else{
                if(strpos($res['errmsg'],"invalid credential, access_token is invalid or not latest hints") === 0){
                    $this->getAccessToken(true);
                }
                return false;
            }

            if ($access_token) {
                $data['access_token_expire_time'] = time() + (int)WechatConfig::EXPIRE_ACCESS_TOKEN;
                $data['access_token'] = $access_token;
                db("wechat_token")->where("id",1)->update($data);
            }
        } else {
            $access_token = $data->access_token;
        }
        return $access_token;
    }
}

