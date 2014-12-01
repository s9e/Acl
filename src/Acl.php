<?php

/**
* @package   s9e\Acl
* @copyright Copyright (c) 2010-2014 The s9e Authors
* @license   http://www.opensource.org/licenses/mit-license.php The MIT License
*/
namespace s9e\Acl;

class Acl
{
	/**
	* Magic value used to represent any scope value
	*/
	const WILDCARD = '';

	/**
	* @var array
	*/
	protected $acl;

	/**
	* 
	*
	* @return void
	*/
	public function construct(array $acl)
	{
		$this->acl = $acl;
	}

	/**
	* 
	*
	* @return void
	*/
	public function isAllowed($action, $scope = [])
	{
		if (!isset($this->acl[$action]))
		{
			return false;
		}

		$n = $this->getBitNumber($perm, $this->normalizeScope($perm, $scope));

		return (bool) (ord($this->acl[$action][self::KEY_BITFIELD][$n >> 3]) & (1 << ($n & 7)));
	}

	/**
	* 
	*
	* @return array
	*/
	protected function normalizeScope($action, $scope)
	{
		if ($scope instanceof Resource)
		{
			$scope = $scope->getAclReaderScope();
		}

		if ($scope === self::WILDCARD)
		{
			$scope = array_fill_keys(array_keys($this->acl[$action][self::KEY_SCOPE_OFFSETS]), self::WILDCARD);
		}
		
		if (!is_array($scope))
		{
			throw new InvalidArgumentException('Invalid scope');
		}

		return $scope;
	}

	/**
	* 
	*
	* @return integer
	*/
	protected function getBitNumber($action, array $scope)
	{
		list($bitfield, $actionOffsets, $scopeOffsets) = $this->acl[$action];
		$n = (isset($actionOffsets[$action])) ? $actionOffsets[$action] : 0;

		foreach ($scope as $dimName => $scopeValue)
		{
			if (isset($scopeOffsets[$dimName][$scopeValue]))
			{
				$n += $scopeOffsets[$dimName][$scopeValue];
			}
		}

		return $n;
	}
}