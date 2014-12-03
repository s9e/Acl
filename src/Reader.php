<?php

/**
* @package   s9e\Acl
* @copyright Copyright (c) 2010-2014 The s9e Authors
* @license   http://www.opensource.org/licenses/mit-license.php The MIT License
*/
namespace s9e\Acl;

class Reader
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
	* Constructor
	*
	* @return void
	*/
	public function construct(array $acl)
	{
		$this->acl = $acl;
	}

	/**
	* Test whether given action is allowed in given scope
	*
	* @param  string         $action Permission action
	* @param  array|Resource $scope  Permission scope
	* @return bool
	*/
	public function isAllowed($action, $scope = [])
	{
		if (!isset($this->acl[$action]))
		{
			return false;
		}

		if ($this->acl[$action] === true)
		{
			return true;
		}

		$n = $this->getBitNumber($action, $this->normalizeScope($action, $scope));

		return (bool) (ord($this->acl[$action][0][$n >> 3]) & (1 << ($n & 7)));
	}

	/**
	* Normalize the scope argument of a public API method
	*
	* @param  string         $action Permission action
	* @param  array|Resource $scope  Permission scope
	* @return array                  Normalized permission scope
	*/
	protected function normalizeScope($action, $scope)
	{
		if ($scope instanceof Resource)
		{
			$scope = $scope->getAclAttributes();
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
	* Return the bit number of given permission
	*
	* @param  string $action Permission action
	* @param  array  $scope  Permission scope
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