<?php

/**
* @package   s9e\Acl
* @copyright Copyright (c) 2010-2014 The s9e Authors
* @license   http://www.opensource.org/licenses/mit-license.php The MIT License
*/
namespace s9e\Acl;

interface Resource
{
	/**
	* Return the attributes that can be used to control access to this resource
	*
	* This should return any relevant attribute by which access to this resource is controlled.
	* For example: ['id' => 123, 'category' => 456]
	*
	* @return array Associative array of attribute values
	*/
	public function getAclAttributes();

	/**
	* Return the ACL scope that uniquely identify this resource
	*
	* Most commonly it should return ['id' => $this->id]
	*
	* @return array Associative array of attribute values
	*/
	public function getAclScope();
}