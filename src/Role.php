<?php

/**
* @package   s9e\Acl
* @copyright Copyright (c) 2010-2011 The s9e Authors
* @license   http://www.opensource.org/licenses/mit-license.php The MIT License
*/
namespace s9e\Acl;

class Role extends Acl
{
	/**
	* @var string Name of this role
	*/
	protected $name;

	/**
	* @param string $name Name of this role
	*/
	public function __construct($name)
	{
		$this->name = $name;
	}

	public function getName()
	{
		return $this->name;
	}
}