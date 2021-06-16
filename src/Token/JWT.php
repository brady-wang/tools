<?php


namespace Brady\Token;


class JWT
{
    public $expireTime = 24 * 3600 * 7;
    public $secretKey = "123456";
    public $alg = "HS256";
    public $typ = "JWT";
    public $algMethod = "sha256";

    public $header;

    /**
     * JWT constructor.
     * @param string $secretKey
     * @param int $expireTime
     */
    public function __construct($secretKey = "", $expireTime = 0)
    {
        if (!empty($expireTime)) $this->expireTime = $expireTime;

        if (!empty($secretKey)) $this->secretKey = $secretKey;

        $this->header = [
            'alg' => $this->alg, //生成signature的算法
            'typ' => $this->typ    //类型
        ];
    }

    /**
     * @return int
     */
    public function getExpireTime(): int
    {
        return $this->expireTime;
    }

    /**
     * @param int $expireTime
     */
    public function setExpireTime(int $expireTime)
    {
        $this->expireTime = $expireTime;
    }

    /**
     * @return string
     */
    public function getSecretKey(): string
    {
        return $this->secretKey;
    }

    /**
     * @param string $secretKey
     */
    public function setSecretKey(string $secretKey)
    {
        $this->secretKey = $secretKey;
    }

    /**
     * @return string
     */
    public function getAlg(): string
    {
        return $this->alg;
    }

    /**
     * @param string $alg
     */
    public function setAlg(string $alg)
    {
        $this->alg = $alg;
    }

    /**
     * @return string
     */
    public function getTyp(): string
    {
        return $this->typ;
    }

    /**
     * @param string $typ
     */
    public function setTyp(string $typ)
    {
        $this->typ = $typ;
    }

    /**
     * Encodes to base64url
     *
     * @param string $data
     * @return string
     */
    public function base64UrlEncode($data)
    {
        return str_replace('=', '', strtr(base64_encode($data), '+/', '-_'));
    }

    /**
     * Decodes from base64url
     *
     * @param string $data
     * @return string
     */
    public function base64UrlDecode($data)
    {
        if ($remainder = strlen($data) % 4) {
            $data .= str_repeat('=', 4 - $remainder);
        }

        return base64_decode(strtr($data, '-_', '+/'));
    }

    /**
     * HMACSHA256签名   https://jwt.io/  中HMACSHA256签名实现
     * @param string $input 为base64UrlEncode(header).".".base64UrlEncode(payload)
     * @param string $key 秘钥
     * @param string $alg 算法方式
     * @return mixed
     */
    private function signature(string $input, string $key)
    {

        // https://www.php.net/manual/zh/function.hash-hmac.php
        return $this->base64UrlEncode(hash_hmac($this->algMethod, $input, $key, true));
    }

    /**
     * 获取 token
     * @param array $payload
     * @return string
     */
    public function getToken(array $payload)
    {
        $payload['expireTime'] = time() + $this->expireTime;

        $payload = array_merge($payload, $payload);
        $base64header = $this->base64UrlEncode(json_encode($this->header, JSON_UNESCAPED_UNICODE));
        $base64payload = $this->base64UrlEncode(json_encode($payload, JSON_UNESCAPED_UNICODE));
        return $base64header . '.' . $base64payload . '.' . $this->signature($base64header . '.' . $base64payload, $this->secretKey);
    }

    public function validateToken($token)
    {
        $tokens = explode('.', $token);

        if (count($tokens) != 3)
            return false;

        list($base64header, $base64payload, $sign) = $tokens;

        //获取jwt算法
        $base64decodeheader = json_decode($this->base64UrlDecode($base64header), JSON_OBJECT_AS_ARRAY);
        if (empty($base64decodeheader['alg']))
            return false;

        //签名验证
        if ($this->signature($base64header . '.' . $base64payload, $this->secretKey) !== $sign)
            return false;

        $payload = json_decode($this->base64UrlDecode($base64payload), JSON_OBJECT_AS_ARRAY);

        //过期时间小宇当前服务器时间验证失败
        if (isset($payload['expireTime']) && $payload['expireTime'] < time())
            return false;

        return $payload;
    }
}