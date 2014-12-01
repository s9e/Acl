<?php

/**
* @package   s9e\Acl
* @copyright Copyright (c) 2010-2014 The s9e Authors
* @license   http://www.opensource.org/licenses/mit-license.php The MIT License
*/
namespace s9e\Acl;

class Matrix
{
	/**
	* Internal value used for granted permissions
	*/
	const ALLOW = 1;

	/**
	* Internal value used for revoked permissions
	*/
	const DENY = 0;

	/**
	* @var array List of settings, grouped by action
	*/
	protected $acl;

	/**
	* @var array Multi-dimensional array containing the permissions granted by given permission.
	*            First level uses the source (grantor) permission's action as key, then the
	*            permission index then the target (grantee) permission's action
	*/
	protected $grantees;

	/**
	* @var array Multi-dimensional array containing the permissions that granted given permission.
	*            First level uses the target (grantee) permission's action as key, then the
	*            permission index then the source (grantee) permission's action
	*/
	protected $grantors;

	/**
	* @var array List of parent indices for each individual index
	*/
	protected $inherit;

	/**
	* @var integer Size of the matrix (number of settings per action)
	*/
	protected $matrixSize;

	/**
	* @var array Offsets of each scope value, grouped by dimension name
	*/
	protected $offsets;

	/**
	* Constructor
	*
	* @param  array $settings Actions as keys, arrays of [setting, scope] as values
	* @param  array $rules    "grant" and "require" as keys, [source => targets] as values
	* @return void
	*/
	public function __construct(array $settings, array $rules)
	{
		$this->computeOffsets($settings);
		$this->fillMatrix($settings);
		$this->solve($rules);
	}

	/**
	* Return the generated bitfield for each action
	*
	* The bitfields are represented as strings made of 0s and 1s
	*
	* @return array Actions as keys, bitfields as values
	*/
	public function getBitfields()
	{
		return array_map(
			function ($settings)
			{
				return implode('', array_map('intval', $settings));
			},
			$this->acl
		);
	}

	/**
	* Return the offsets of each dimension's scope values
	*
	* @return array Dimensions' names as keys, arrays of [scope value => offset] as values
	*/
	public function getOffsets()
	{
		return $this->offsets;
	}

	/**
	* Apply given grant rule to every permission
	*
	* Grant rules are applied when there's no setting for a permission. If a permission is already
	* set, it's either allowed and we don't have to do anything or it's denied and we must not
	* override it. The method records which permissions were granted by which, and vice-versa
	*
	* @param  string $srcAction Source action (grantor)
	* @param  string $trgAction Target action (grantee)
	* @return bool              Whether a new permission has been granted
	*/
	protected function applyGrantRule($srcAction, $trgAction)
	{
		$granted = false;
		foreach (array_filter($this->acl[$srcAction]) as $k => $setting)
		{
			if (!isset($this->acl[$trgAction][$k]) || isset($this->grantees[$trgAction][$k]))
			{
				if (!isset($this->acl[$trgAction][$k]))
				{
					$granted = true;
				}

				$this->acl[$trgAction][$k] = self::ALLOW;
				$this->grantees[$srcAction][$k][$trgAction] = $trgAction;
				$this->grantors[$trgAction][$k][$srcAction] = $srcAction;
			}
		}

		return $granted;
	}

	/**
	* Apply all given grant rules
	*
	* @param  array Source actions as keys, target actions as values
	* @return void
	*/
	protected function applyGrantRules(array $rules)
	{
		$this->grantees = $this->grantors = [];
		$this->applyRules('applyGrantRule', $rules);
	}

	/**
	* Apply inheritance to every permission
	*
	* @return void
	*/
	protected function applyInheritance()
	{
		foreach ($this->acl as $action => &$settings)
		{
			$i = 0;
			while (++$i < $this->matrixSize)
			{
				foreach ($this->inherit[$i] as $inherit)
				{
					if ($settings[$i] === self::DENY)
					{
						break;
					}

					if (isset($settings[$inherit]))
					{
						$settings[$i] = $settings[$inherit];
					}
				}
			}
		}
	}

	/**
	* Apply all given require rules
	*
	* @param  array Source actions as keys, target actions as values
	* @return void
	*/
	protected function applyRequireRules(array $rules)
	{
		$this->applyRules('applyRequireRule', $rules);

		// TODO: test A grant B, C grant D, B grant C, B require C
		// TODO: A grant C, B require C, C require D
		// TODO: A grant C, B require C, A require D
	}

	/**
	* Apply given require rule to every permission
	*
	* @param  string $srcAction Source action
	* @param  string $trgAction Target action (the required permission)
	* @return bool              Whether a permission has been revoked
	*/
	protected function applyRequireRule($srcAction, $trgAction)
	{
		$revoked = false;
		foreach (array_filter($this->acl[$srcAction]) as $k => $setting)
		{
			if ($this->acl[$trgAction][$k] !== self::ALLOW)
			{
				$this->acl[$srcAction][$k] = $this->acl[$trgAction][$k];
				$revoked = true;

				if (isset($this->grantees[$srcAction][$k]))
				{
					$this->cancelGrantsFrom($srcAction, $k);
				}
			}
		}

		return $revoked;
	}

	/**
	* Apply given set of rules to the ACL using given method
	*
	* @param  string $methodName Method's name
	* @param  array  Source actions as keys, target actions as values
	* @return void
	*/
	protected function applyRules($methodName, array $rules)
	{
		do
		{
			$continue = false;
			foreach ($rules as $srcAction => $trgActions)
			{
				foreach ($trgActions as $trgAction)
				{
					if ($this->$methodName($srcAction, $trgAction))
					{
						$continue = true;
					}
				}
			}
		}
		while ($continue);
	}

	/**
	* Cancel a single permission grant
	*
	* @param  string  $srcAction Source action (grantor)
	* @param  integer $k         Permission index
	* @param  integer $trgAction Target action (grantee)
	* @return void
	*/
	protected function cancelGrant($srcAction, $k, $trgAction)
	{
		unset($this->grantees[$srcAction][$k][$trgAction]);
		unset($this->grantors[$trgAction][$k][$srcAction]);

		if (empty($this->grantors[$trgAction][$k]))
		{
			$this->settings[$trgAction][$k] = null;
			$this->cancelGrantsFrom($trgAction, $k);
		}
	}

	/**
	* Cancel permissions that were uniquely granted by given permission
	*
	* The permissions are only revoked if they were granted by, and only by given permission
	*
	* @param  string  $srcAction Source action (grantor)
	* @param  integer $k         Permission index
	* @return void
	*/
	protected function cancelGrantsFrom($srcAction, $k)
	{
		foreach ($this->grantees[$srcAction][$k] as $trgAction)
		{
			$this->cancelGrant($srcAction, $k, $trgAction);
		}
		unset($this->grantees[$srcAction][$k]);
	}

	/**
	* Compute the inheritance for each setting
	*
	* For each offset, we iterate through the offsets of the other dimensions to compute the offset
	* of the settings that directly inherit from current one. For instance, in a matrix that has 3
	* dimensions x, y and z, if $base points to the offset of the [x:1] setting, we iterate through
	* all possible values for [x:1,y:?] and [x:1,z:?] to add the [x:1] coordinate/offset to the list
	* of offsets they inherit from. The [x:1] setting itself inherits from the global setting, thus
	* all descendants will indirectly inherit from it as well.
	*
	* @param  integer $base
	* @param  array   $dimensions
	* @return void
	*/
	protected function computeInheritance($base = 0, array $dimensions = [])
	{
		if (!$base)
		{
			$this->inherit = array_fill(0, $this->matrixSize, []);
		}

		$unmappedDimensions = array_diff_key($this->offsets, $dimensions);
		$hasMoreDimensions  = (count($unmappedDimensions) > 1);
		foreach ($unmappedDimensions as $dimName => $offsets)
		{
			foreach ($offsets as $offset)
			{
				$this->inherit[$base + $offset][] = $base;

				if ($hasMoreDimensions)
				{
					$this->computeInheritance($base + $offset, $dimensions + [$dimName => 1]);
				}
			}
		}
	}

	/**
	* Compute the scope offsets
	*
	* @param  array $settings Actions as keys, arrays of [setting, scope] as values
	* @return void
	*/
	protected function computeOffsets(array $settings)
	{
		$this->offsets = [];
		$multiplier = 1;
		foreach ($this->collectScopes($settings) as $dimName => $scopeValues)
		{
			// Prepend the wildcard bit to the list of values
			array_unshift($scopeValues, Acl::WILDCARD);

			// The global bit takes offset 0. Each other value takes the offset equal to their
			// one-based index multiplied by the dimension's factor (number of scope values
			// including the wildcard value plus the global bit)
			foreach ($scopeValues as $i => $scopeValue)
			{
				$this->offsets[$dimName][$scopeValue] = ($i + 1) * $multiplier;
			}
			$multiplier *= 1 + count($scopeValues);
		}
	}

	/**
	* Collect all scope values from given settings
	*
	* @param  array $settings Actions as keys, arrays of [setting, scope] as values
	* @return array           Dimensions' names as keys, arrays of [scope value => offset] as values
	*/
	protected function collectScopes(array $settings)
	{
		$scopesValues = [];
		foreach ($settings as $action => $permissions)
		{
			foreach ($permissions as list($setting, $scope))
			{
				foreach ($scope as $dimName => $scopeValue)
				{
					$scopesValues[$dimName][$scopeValue] = $scopeValue;
				}
			}
		}

		ksort($scopesValues);
		foreach ($scopesValues as &$scopeValues)
		{
			sort($scopeValues);
		}

		return $scopesValues;
	}

	/**
	* Fill the matrix with given settings
	*
	* @param  array $settings Actions as keys, arrays of [setting, scope] as values
	* @return void
	*/
	protected function fillMatrix(array $settings)
	{
		$this->resetMatrix(array_keys($settings));

		foreach ($settings as $action => $permissions)
		{
			foreach ($permissions as list($setting, $scope))
			{
				$offset = 0;
				foreach ($scope as $dimName => $scopeValue)
				{
					$offset += $this->offsets[$dimName][$scopeValue];
				}

				if (!isset($this->acl[$offset]) || $setting === self::DENY)
				{
					$this->acl[$action][$offset] = $setting;
				}
			}
		}

		ksort($this->acl);
	}

	/**
	* Fill the wildcard bits of given action's permissions
	*
	* @param  string   $action     Action's name
	* @param  integer  $base       Base index (coordinate for the global setting in given scope)
	* @param  string[] $dimensions Dimensions for which to fill the wildcard bits
	* @return void
	*/
	protected function fillWildcardBits($action, $base, array $dimensions)
	{
		foreach ($dimensions as $k => $dimension)
		{
			$wildcardOffset = $this->offsets[$dimension][Acl::WILDCARD];
			$this->acl[$action][$base + $wildcardOffset] = null;

			$unmappedDimensions = $dimensions;
			unset($unmappedDimensions[$k]);

			foreach ($this->offsets[$dimension] as $offset)
			{
				if (!empty($unmappedDimensions))
				{
					$this->fillWildcardBits($action, $base + $offset, $unmappedDimensions);
				}

				if ($this->acl[$action][$base + $offset] === self::ALLOW)
				{
					$this->acl[$action][$base + $wildcardOffset] = self::ALLOW;
				}
			}
		}
	}

	/**
	* Initialize the ACL matrix for each given action
	*
	* @param  string[] $actions Action names
	* @return void
	*/
	protected function resetMatrix(array $actions)
	{
		// Compute the size of the matrix as the product of its dimensions
		$dimSizes = [];
		foreach ($this->offsets as $dimName => $offsets)
		{
			// We add 1 to account for the global scope (offsets contain the wildcard bit already)
			$dimSizes[$dimName] = 1 + count($offsets);
		}
		$this->matrixSize = array_product($dimSizes);

		// Initialize an empty matrix for each action
		$this->acl = array_fill_keys($actions, array_fill(0, $this->matrixSize, null));
	}

	/**
	* Solve this matrix
	*
	* Will apply inheritance and given rules, then set the wildcard bits
	*
	* @param  array $rules    "grant" and "require" as keys, [source => targets] as values
	* @return void
	*/
	protected function solve(array $rules)
	{
		$this->computeInheritance();

		$rules  += ['grant' => [], 'require' => []];
		$grant   = array_intersect_key($rules['grant'], $this->acl);
		$require = array_intersect_key($rules['require'], $this->acl);

		$hash   = crc32(serialize($this->acl));
		$hashes = [$hash => 1];
		do
		{
			$this->applyInheritance();
			$this->applyGrantRules($grant);
			$this->applyRequireRules($require);

			$hash = crc32(serialize($this->acl));
			if (isset($hashes[$hash]))
			{
				break;
			}
			$hashes[$hash] = 1;
		}
		while (1);

		foreach (array_keys($this->acl) as $action)
		{
			$this->fillWildcardBits($action, 0, array_keys($this->offsets));
		}
	}
}