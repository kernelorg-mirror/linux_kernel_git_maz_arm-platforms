# SPDX-License-Identifier: GPL-2.0
#
# dumpreg.jq: JSON arm64 system register data extractor
#
# Author: Marc Zyngier <maz@kernel.org>
#
# Usage: jq -r --arg REG "XZY_ELx" -f ./dumpreg.jq Registers.json

# Dump a set of semi-pertinent informations (encodings, fields,
# conditions, field position and width) about register XZY_ELx as
# contained in ARM's AARCHMRS_BSD_A_profile JSON tarball.

# Not setting REG will dump the whole register file in one go. While
# this is entertaining, it isn't very useful.

# This can/should be used to populate the arch/arm64/tools/sysreg
# file, instead of copying things by hand.

# The tool currently has a bunch of limitations that users need to be
# aware of, but none that should have a major impact on the usability:

# - All accessors are shown, irrespective of the conditions in which
#   the accessors are actually available

# - All Fields.ConstantField are displayed as UnsignedEnum,
#   irrespective of the signess of the field (as the JSON doesn't
#   carry this information).

# - Value ranges are displayed using '[...]'.

# - Fields are processed and displayed in the order of the JSON
#   source, which may not be the order in the register.

# - Conditional fields may appear multiple times.

# - ... and probably more...

def walknode:
	def walkjoin(s):
		map(walknode) | join(s);

        if   (._type == "AST.Identifier" or ._type == "AST.Integer" or
	      ._type == "Values.Value" or ._type == "AST.Bool" or
	      ._type == "Types.String") then
	     	.value
	elif (._type == "Types.Field") then
		"\(.value.name).\(.value.field)"
	elif (._type == "AST.UnaryOp") then
		"\(.op)(\(.expr | walknode))"
	elif (._type == "AST.Function") then
		"\(.name)(\(.arguments | walkjoin(", ")))"
	elif (._type == "AST.DotAtom") then
		.values | walkjoin(".")
	elif (._type == "AST.BinaryOp") then
		"(\(.left | walknode) \(.op) \(.right | walknode))"
	elif (._type == "Types.RegisterType") then
		.name
	elif (._type == "AST.Type") then
		"\(.name | walknode)"
	elif (._type == "AST.Slice") then
		"\(.left.value):\(.right.value)"
	elif (._type == "AST.Set") then
		.values | map(walknode)
	elif (._type == "AST.Assignment")  then
		"\(.var | walknode) = \(.val | walknode)"
	elif (._type == "AST.TypeAnnotation")  then
		"\(.var | walknode):\(.type | walknode)"
	elif (._type == "AST.SquareOp") then
		"\(.var | walknode)[\(.arguments | walkjoin(", "))]"
	elif (._type == "AST.Return") then
		"return"
	elif (._type == "AST.Concat") then
		"[\(.values | walkjoin(", "))]"
	elif (._type == "AST.Tuple") then
		"(\(.values | walkjoin(", ")))"
	else	# debug catch-all
		.
	end;

def range:
	. as { _type: $type, start: $start, width: $width } |
	if ($width == 1) then
		"\($start)"
	else
		"\($start + $width - 1):\($start)"
	end;

def fld:
	(if (.condstr.text) then "\t\(.condstr.text)"
	 else "" end) as $cond |
	"\(.type)\t\(.range | range)\t\(.name)\($cond)";

def condition(source):
	"# \(source) cond: \(.condition | walknode)";

def unquote:
	"'" as $q | (ltrimstr($q) | rtrimstr($q));

def binvalue:
	.value | unquote as $v | "\t0b\($v)\tVAL_\($v)";

def dumpconstants:
	if   (._type == "Values.Value") then
		binvalue
	elif (._type == "Values.ValueRange") then
		(.start | binvalue), "\t[...]", (.end | binvalue)
	elif (._type == "Values.ConditionalValue") then
		"\(.values.values[] | dumpconstants)\t\(condition("Value"))"
 	else	# Debug catch all
		.
	end;

def dumpenum:
	# Things like SMIDR_EL1.Affinity do not describe
	# the value range, hence the []? hack below.
	(.value.constraints.values[]? | dumpconstants);

def genarrayelt(n; bpf):
	"<\(.index_variable)>" as $v |
	(.rangeset | reverse) as $rs |
	($rs | length) as $nrs |
	{
		_type: (if (bpf > 1) then "Fields.ConstantField"
			else "Fields.Field" end),
		name: (.name | sub($v; "\(n)")),
		rangeset: [
			{
				_type: "Range",
				start: (if ($nrs > 1) then $rs[n].start
				        else $rs[0].start + n * bpf end),
				width: bpf
			}
		],
		value: { constraints: .values },
		condstr: (if (.condstr) then
			    { text: (.condstr.text | sub($v; "\(n)")) }
			  else
			    null
			  end)
	};

def genarray:
	# Oh the fun we're having: convert each element of the array
	# into its own architectural field, warts and all. Additional
	# fun is provided to compute the number of bits per fields,
	# as the elements can be spread over multiple rangesets.
	. as $field |
	.indexes[0].width as $nr |
	((reduce .rangeset[].width as $sz (0; . + $sz)) / $nr) as $bpf |
	[ range(0; $nr) ] | reverse | map(. as $n | $field | genarrayelt($n; $bpf));

# For each range of a field, unpack it as start and width, and
# apply it to each range of the parent field (used as a base).
# Although this can result in a combinatorial explosion, the
# likely case is that one of the two sets is of size one.
def mergerangesets(base):
	.[] |
	.start as $s |
	.width as $w |
	base | map({
			_type: "Range",
			start: (.start + $s),
			width: ([ $w, .width ] | min)
		   });

def depthstr(depth):
	[ range(0, depth) ] | map(32, 32) | implode;

def walkfields(depth):
	depthstr(depth) as $dep |
	if   (._type == "Fields.Reserved" and .value == "RES0") then
		{ type: "Res0", name: "", range: .rangeset[] } |
		"\($dep)\(fld)"
	elif (._type == "Fields.Reserved" and .value == "RES1") then
		{ type: "Res1", name: "", range: .rangeset[] } |
		"\($dep)\(fld)"
	elif (._type == "Fields.ConditionalField") then
		# Propagate the condition text over all conditional
		# fields by injecting a new ".condstr.text" field.
		# Also, the ranges must be combined as they nest.
		.rangeset as $r |
		.fields | map(condition("Field") as $c |
			      .field.condstr |= { text: $c }) |
			  map(.field.rangeset |= mergerangesets($r)) |
		.[] | .field | walkfields(depth)
	elif (._type == "Fields.Dynamic") then
		({ type: "Field", name: .name, range: .rangeset[], condstr: .condstr } | fld),
	     	(.rangeset as $r | .instances[] |
		 ((.display // .name // "Instance") as $src |
		  "\(depthstr(depth + 1))\(condition($src))",
		  # Remap the rangesets to display the absolute range
		  (.values | map(.rangeset |= mergerangesets($r)) |
		   .[] | walkfields(depth + 1))))
	elif (._type == "Fields.ConstantField") then
		({ type: "UnsignedEnum", name: .name, range: .rangeset[], condstr: .condstr } |
		 "\($dep)\(fld)"),
		dumpenum,
		"EndEnum"
	elif (._type == "Fields.Field") then
		{ type: "Field", name: .name, range: .rangeset[], condstr: .condstr } |
		"\($dep)\(fld)"
	elif (._type == "Fields.Reserved") then
		{ type: "Field", name: .value, range: .rangeset[], condstr: .condstr } |
		"\($dep)\(fld)"
	elif (._type == "Fields.ImplementationDefined") then
		{ type: "Field", name: (.name // "IMPDEF"), range: .rangeset[], condstr: .condstr } |
		"\($dep)\(fld)"
	elif (._type == "Fields.Array" or ._type == "Fields.Vector") then
	     	genarray | .[] | walkfields(depth)
 	else	# Debug catch all
		.
	end;

def tautology:
	(.condition.value == true);

def walkreg:
	(.fieldsets | length) as $l |
	.fieldsets[] |
	  (if ($l > 1 or (tautology | not)) then condition("Fieldset") else empty end),
	  (.values[] | walkfields(0));

def bin_to_i:
	def bintoi:
		(length - 1) as $e |
		((.[0] - 48) * ($e | exp2)) + (if ($e > 0) then .[1:] | bintoi
				     	       else 0 end);
	explode | bintoi;

def computeencoding:
	if (.) then
		if   (._type == "Values.Value") then .value | unquote | bin_to_i
		elif (._type == "Values.Group") then .value
		elif (._type == "Values.EquationValue") then "\(.value)[\(.slice[] | range)]"
		else . # Debug catch all
		end
	else
		"#Imm"
	end;

def encodings:
	.encodings | [ .op0, .op1, .CRn, .CRm, .op2 ] | map(computeencoding);

def accessorencoding:
	(.name | ltrimstr("A64.")) as $name |
	.encoding[] | "\(.asmvalue)\t\(encodings)\t\($name)";

def accessors:
	.accessors[] |
	accessorencoding;

def regcondition:
	if (tautology | not) then condition("Reg") else empty end;

.[] | select (._type == "Register" or ._type == "RegisterArray") |
      select (.state == "AArch64" and
	      ($ARGS.named.REG == null or .name == $ARGS.named.REG)) |
      "# \(.name)",accessors,regcondition,walkreg
