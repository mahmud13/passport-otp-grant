<?php

/**
 * @author mahmud
 */

namespace Amin3536\PassportOtpGrant\otpGrant;

use League\OAuth2\Server\Exception\OAuthServerException;

trait HasOTP
{
    protected function getPhoneNumberColumn()
    {
        return config('auth.otp.username', 'phone');
    }


    protected function getOTPColumn()
    {
        return config('auth.otp.otp', 'otp');
    }


    protected function getOTPExpireTime()
    {
        return config('auth.otp.expires_in', 15);
    }

    /**
     * @param $phoneNumber
     * @param $otp
     * @return mixed
     */
    public function validateForOTPCodeGrant($phoneNumber, $otp)
    {
        $user = $this->where($this->getPhoneNumberColumn(), $phoneNumber)->first();

        if (!$user) {
            throw OAuthServerException::invalidRequest('phone_number', 'phone_number');
        }
        if (method_exists($this, 'getOtp')) {
            $otp = $user->getOtp($otp);
            if (!$otp) {
                throw OAuthServerException::invalidRequest('otp', 'otp is wrong ');
            }

            if ($otp->updated_at->diffInMinutes(now()) > $this->getOTPExpireTime()) {
                throw  OAuthServerException::invalidRequest('otp', 'otp code expired try to get it again');
            }
        } else {
            $orig_otp = $user->{$this->getOTPColumn()};
            if (!$orig_otp || $orig_otp != $otp) {
                throw OAuthServerException::invalidRequest('otp', 'otp is wrong ');
            }
            if ($user->updated_at->diff(now())->format('%i min') > $this->getOTPExpireTime()) {
                throw  OAuthServerException::invalidRequest('otp', 'otp code expired try  get it  again');
            }
            $this->removeOtp($user);
        }


        return $user;
    }

    public function removeOtp($user)
    {
        $user->save([$this->getOTPColumn() => null]);
    }
}
