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
    private $appId;
    private $appSecret;

    public function __construct($appId, $appSecret) {
        $this->appid = WechatConfig::APPID;
        $this->appSecret = WechatConfig::APPSECRET;
    }

    public function getSignPackage($url = NULL) {
        $jsapiTicket = $this->getJsApiTicket();

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
            "appId"     => $this->appId,
            "nonceStr"  => $nonceStr,
            "timestamp" => $timestamp,
            "url"       =>$url,
            "signature" => $signature,
            "rawString" => $string,
        );
        return $signPackage;
    }



    public function getJsApiTicket() {
        // jsapi_ticket 应该全局存储与更新，以下代码以写入到文件中做示例
        $data = Cache::get("jsapiTicket");
        if (!$data || $data['expire_time'] < time()) {
            $accessToken = $this->getAccessToken();
            // 如果是企业号用以下 URL 获取 ticket
            $url = sprintf(WechatConfig::GET_JSAPI_TICKET_URL, $accessToken);
            $res = json_decode(Common::postCurl($url, 'GET'), true);

            $ticket = $res['ticket'];
            if ($ticket) {
                $data['expire_time'] = time() + (int)WechatConfig::EXPIRE_ACCESS_TOKEN;
                $data['jsapi_ticket'] = $ticket;
                Cache::set("jsapiTicket",$data);
            }
        } else {
            $ticket = $data['jsapi_ticket'];
        }

        return $ticket;
    }

    public function getAccessToken() {
        // access_token 应该全局存储与更新，以下代码以写入到文件中做示例
//    $data = json_decode($this->get_php_file("data/file/access_token.php"));
        $data = Cache::get("accessToken");
        if (!$data || $data['expire_time'] < time()) {

            // 如果是企业号用以下URL获取access_token
            $url = sprintf(WechatConfig::GET_ACCESS_TOKEN_URL, $this->appid, $this->appSecret);
            $res = json_decode(Common::postCurl($url, 'GET'), true);
            $access_token = $res['access_token'];
            if ($access_token) {
                $data['expire_time'] = time() + (int)WechatConfig::EXPIRE_ACCESS_TOKEN;
                $data['access_token'] = $access_token;
//        $this->set_php_file("../../access_token.php", json_encode($data));
                Cache::set("accessToken",$data);
            }
        } else {
            $access_token = $data->access_token;
        }
        return $access_token;
    }

    private function get_php_file($filename) {
        return trim(substr(file_get_contents($filename), 15));
    }
    private function set_php_file($filename, $content) {
        file_put_contents($filename,"<?php exit();?>" . $content);
    }
}

