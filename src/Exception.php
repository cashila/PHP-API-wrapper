<?php

namespace Cashila\Api;

class Exception extends \Exception {
  protected $_userMessage;

  public function setUserMessage($message) {
    $this->_userMessage = $message;
  }

  public function getUserMessage() {
    return $this->_userMessage;
  }
}
