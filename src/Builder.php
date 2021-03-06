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
	* @var BitPacker
	*/
	public $bitPacker;

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
	* Constructor
	*
	* @return void
	*/
	public function __construct()
	{
		$this->bitPacker = new BitPacker;
	}

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

		$this->add($srcAction, [], null);
		$this->add($trgAction, [], null);
		$this->rules[$rule][$srcAction][$trgAction] = $trgAction;
	}

	/**
	* Grant a permission for given scope
	*
	* @param  string         $action Action name
	* @param  array|Resource $scope  Permission scope
	* @return void
	*/
	public function allow($action, $scope = [])
	{
		$this->add($action, $this->getScope($scope), Matrix::ALLOW);
	}

	/**
	* Revoke a permision for given scope
	*
	* @param  string         $action Action name
	* @param  array|Resource $scope  Permission scope
	* @return void
	*/
	public function deny($action, $scope = [])
	{
		$this->add($action, $this->getScope($scope), Matrix::DENY);
	}

	/**
	* Return an instance of the ACL reader
	*
	* @return Reader
	*/
	public function getReader()
	{
		return new Reader($this->getReaderConfig());
	}

	/**
	* Return the ACL config as an array
	*
	* @return array
	*/
	public function getReaderConfig()
	{
		$acl = [];
		foreach ($this->getActionsGroups() as $actions)
		{
			$grant    = array_intersect_key($this->rules['grant'], array_flip($actions));
			$require  = array_intersect_key($this->rules['require'], array_flip($actions));
			$settings = array_intersect_key($this->settings, array_flip($actions));

			$acl += $this->finalize(new Matrix($settings, $grant, $require));
		}
		ksort($acl);

		return $acl;
	}

	//==========================================================================
	// Internals
	//==========================================================================

	/**
	* Add a permission
	*
	* @param  string  $action  Permission's action
	* @param  array   $scope   Permission's scope
	* @param  integer $setting Permission's setting
	* @return void
	*/
	protected function add($action, $scope, $setting)
	{
		if ($action === '')
		{
			throw new InvalidArgumentException('Action cannot be an empty string');
		}

		$this->settings[$action][] = [$scope, $setting];
	}

	/**
	* Serialize a matrix into a compact representation
	*
	* @see Acl::getBitNumber
	*
	* @param  Matrix $matrix
	* @return array<array|bool> Action names as keys. Values are either TRUE for global permissions or for local permission an array containing: a bitfield, an array containing the offsets of each action in the bitfield, and an array containing the offsets of each scope value for each dimension
	*/
	protected function finalize(Matrix $matrix)
	{
		$bitfields = array_filter(
			$matrix->getBitfields(),
			function ($bitfield)
			{
				return (strpos($bitfield, '1') !== false);
			}
		);
		$actions = array_keys($bitfields);

		$scopeOffsets = $matrix->getOffsets();
		if (empty($scopeOffsets))
		{
			// Global permissions can be represented as a boolean
			return array_fill_keys($actions, true);
		}

		$actionOffsets  = [];
		$mergedBitfield = $this->bitPacker->merge($bitfields);
		foreach ($bitfields as $action => $bitfield)
		{
			$actionOffsets[$action] = strpos($mergedBitfield, $bitfield);
		}

		$config = [
			$this->bitPacker->toBin($mergedBitfield),
			array_filter($actionOffsets),
			$scopeOffsets
		];
		$acl = [];
		foreach ($actions as $action)
		{
			$acl[$action] =& $config;
		}

		return $acl;
	}

	/**
	* Return all actions referenced in this ACL
	*
	* Returns all actions used in permissions as well as granted or required by a rule
	*
	* @return string[]
	*/
	protected function getActions()
	{
		$actions = array_keys($this->settings);
		foreach ($this->rules as $ruleName => $rules)
		{
			foreach ($rules as $srcAction => $trgActions)
			{
				$actions   = array_merge($actions, $trgActions);
				$actions[] = $srcAction;
			}
		}

		return $actions;
	}

	/**
	* Return the dimensions used by each action referenced in this ACL
	*
	* Takes the dimensions used in permission scopes into account, as well as the dimensions used by
	* related rules
	*
	* @return array Array of lists of strings
	*/
	protected function getActionsDimensions()
	{
		$actionDimensions = array_fill_keys($this->getActions(), []);
		foreach ($this->settings as $action => $permissions)
		{
			foreach ($permissions as $permission)
			{
				$actionDimensions[$action] += $permission[0];
			}
		}

		// Keep looping as long as the number of dimensions used by actions keep increasing
		$relations = $this->getRulesRelationships();
		do
		{
			$oldCount = count($actionDimensions, COUNT_RECURSIVE);
			foreach ($relations as $relation)
			{
				list($srcAction, $trgAction) = $relation;
				$actionDimensions[$srcAction] += $actionDimensions[$trgAction];
				$actionDimensions[$trgAction] += $actionDimensions[$srcAction];
			}
			$newCount = count($actionDimensions, COUNT_RECURSIVE);
		}
		while ($newCount > $oldCount);

		return array_map('array_keys', $actionDimensions);
	}

	/**
	* Return a list of actions for each set of dimensions
	*
	* @return array Array of arrays of strings
	*/
	protected function getActionsGroups()
	{
		$groups = [];
		foreach ($this->getActionsDimensions() as $action => $dimensions)
		{
			sort($dimensions);
			$groups[serialize($dimensions)][] = $action;
		}

		return $groups;
	}

	/**
	* Return a list of the targets used in rules
	*
	* @return array Array of [source, target]
	*/
	protected function getRulesRelationships()
	{
		// Retrieve the relationships between actions
		$peers = [];
		foreach ($this->rules as $ruleName => $rules)
		{
			foreach ($rules as $srcAction => $trgActions)
			{
				foreach ($trgActions as $trgAction)
				{
					$peers[] = [$srcAction, $trgAction];
				}
			}
		}

		return $peers;
	}

	/**
	* Validate, normalize and optionally retrieve from a resource a permission scope
	*
	* @param  array|Resource $scope Original scope
	* @return array                 Validated, normalized scope
	*/
	protected function getScope($scope)
	{
		if ($scope instanceof Resource)
		{
			$scope = $scope->getAclScope();
		}

		if (!is_array($scope))
		{
			throw new InvalidArgumentException('Scope must be an array or an instance of ' . __NAMESPACE__ . '\\Resource');
		}

		return $this->normalizeScope($scope);
	}

	/**
	* Normalize a permission scope
	*
	* @param  array $scope Original scope
	* @return array        Normalized scope, typed and sorted
	*/
	protected function normalizeScope(array $scope)
	{
		ksort($scope);
		foreach ($scope as $dimName => $scopeValue)
		{
			if ($dimName === '')
			{
				throw new InvalidArgumentException('Scope dimensions must have a name');
			}

			if ($scopeValue === '')
			{
				throw new InvalidArgumentException('Scope value for ' . $dimName . ' cannot be empty');
			}

			if (!is_integer($scopeValue) && !is_string($scopeValue))
			{
				throw new InvalidArgumentException('Invalid type for ' . $dimName . ' scope: integer or string expected, ' . gettype($scopeValue) . ' given');
			}
		}

		return $scope;
	}
}