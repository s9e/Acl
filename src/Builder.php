<?php

/**
* @package   s9e\Acl
* @copyright Copyright (c) 2010-2014 The s9e Authors
* @license   http://www.opensource.org/licenses/mit-license.php The MIT License
*/
namespace s9e\Acl;

use InvalidArgumentException;

class Builder
{
	/**
	* @var array List of rules directly associated with this ACL
	*/
	protected $rules = [
		'grant'   => [],
		'require' => []
	];

	/**
	* @var array List of settings directly associated with this ACL, grouped by action name
	*/
	protected $settings = [];

	/**
	* Add a rule
	*
	* @param  string $srcAction Action name
	* @param  string $rule      Rule type: either "grant" or "require"
	* @param  string $trgAction Action name
	* @return void
	*/
	public function addRule($srcAction, $rule, $trgAction)
	{
		if ($rule !== 'grant' && $rule !== 'require')
		{
			throw new InvalidArgumentException("Unsupported rule '" . $rule . "'");
		}

		$this->rules[$rule][$srcAction][$trgAction] = $trgAction;
	}

	/**
	* Grant a permission for given scope
	*
	* @param  string         $action Action name
	* @param  array|Resource $scope  Permission scope
	* @return void
	*/
	public function allow($action, $scope)
	{
		$this->add(Matrix::ALLOW, $action, $scope);
	}

	/**
	* Revoke a permision for given scope
	*
	* @param  string         $action Action name
	* @param  array|Resource $scope  Permission scope
	* @return this
	*/
	public function deny($action, $scope)
	{
		$this->add(Matrix::DENY, $action, $scope);
	}

	/**
	* 
	*
	* @return array
	*/
	public function getConfig()
	{
	}

	//==========================================================================
	// Internals
	//==========================================================================

	/**
	* Add or replace a action setting for given scope
	*
	* @return void
	*/
	protected function add($setting, $action, $scope)
	{
		if ($scope instanceof Resource)
		{
			$scope = $scope->getAclScope();
		}

		if (!is_array($scope))
		{
			throw new InvalidArgumentException('Scope must be an array or an instance of ' . __NAMESPACE__ . '\\Resource');
		}

		$this->settings[$action][] = [$setting, $this->normalizeScope($scope)];
	}

	/**
	* 
	*
	* @return array
	*/
	protected function normalizeScope(array $scope)
	{
		ksort($scope);
		foreach ($scope as $dimName => &$scopeValue)
		{
			switch (gettype($scopeValue))
			{
				case 'integer':
					// nothing to do
					break;

				case 'string':
					if ($scopeValue === '')
					{
						throw new InvalidArgumentException('Scope value for ' . $dimName . ' cannot be empty');
					}

					// Numbers passed as strings may get cast to integer when they are used as
					// array keys, which happens quite often in our routines. We make sure that
					// this cast happens right now before any processing occurs
					$scopeValue = key([$scopeValue => 0]);
					break;

				default:
					throw new InvalidArgumentException('Invalid type for ' . $dimName . ' scope: integer or string expected, ' . gettype($scopeValue) . ' given');
			}
		}
		unset($scopeValue);

		return $scope;
	}
}