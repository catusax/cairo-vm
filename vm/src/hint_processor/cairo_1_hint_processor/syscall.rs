use crate::types::{exec_scope::ExecutionScopes, relocatable::MaybeRelocatable};
use crate::vm::errors::hint_errors::HintError;
use ark_ff::BigInteger;
use ark_ff::PrimeField;
use ark_secp256k1 as secp256k1;
use crate::Felt252;
use num_bigint::BigUint;
use num_integer::Integer;
use num_traits::Zero;
use starknet_types_core::felt::Felt;

/// Resulting options from a syscall.
pub enum SyscallResult {
    /// The syscall was successful.
    Success(Vec<MaybeRelocatable>),
    /// The syscall failed, with the revert reason.
    Failure(Vec<Felt252>),
}

macro_rules! fail_syscall {
    ($reason:expr) => {
        let f = Felt252::from_bytes_be($reason);
        return Ok(SyscallResult::Failure(vec![f]))
    };
    ($existing:ident, $reason:expr) => {
        $existing.push(Felt252::from_bytes_be($reason));
        return Ok(SyscallResult::Failure($existing))
    };
}

/// Executes the `secp256k1_new_syscall` syscall.
pub fn secp256k1_new(
    #[allow(unused)]
    gas_counter: &mut usize,
    x: BigUint,
    y: BigUint,
    exec_scopes: &mut ExecutionScopes,
) -> Result<SyscallResult, HintError> {
    let modulus = <secp256k1::Fq as PrimeField>::MODULUS.into();
    if x >= modulus || y >= modulus {
        fail_syscall!(b"Coordinates out of range        ");
    }
    let p = if x.is_zero() && y.is_zero() {
        secp256k1::Affine::identity()
    } else {
        secp256k1::Affine::new_unchecked(x.into(), y.into())
    };
    Ok(SyscallResult::Success(
        if !(p.is_on_curve() && p.is_in_correct_subgroup_assuming_on_curve()) {
            vec![1.into(), 0.into()]
        } else {
            let ec = get_secp256k1_exec_scope(exec_scopes)?;
            let id = ec.ec_points.len();
            ec.ec_points.push(p);
            vec![0.into(), id.into()]
        },
    ))
}

/// Executes the `secp256k1_add_syscall` syscall.
pub fn secp256k1_add(
    #[allow(unused)]
    gas_counter: &mut usize,
    exec_scopes: &mut ExecutionScopes,
    p0_id: usize,
    p1_id: usize,
) -> Result<SyscallResult, HintError> {
    let ec = get_secp256k1_exec_scope(exec_scopes)?;
    let p0 = &ec.ec_points[p0_id];
    let p1 = &ec.ec_points[p1_id];
    let sum = *p0 + *p1;
    let id = ec.ec_points.len();
    ec.ec_points.push(sum.into());
    Ok(SyscallResult::Success(vec![id.into()]))
}

/// Executes the `secp256k1_mul_syscall` syscall.
pub fn secp256k1_mul(
    #[allow(unused)]
    gas_counter: &mut usize,
    p_id: usize,
    scalar: BigUint,
    exec_scopes: &mut ExecutionScopes,
) -> Result<SyscallResult, HintError> {
    let ec = get_secp256k1_exec_scope(exec_scopes)?;
    let p = &ec.ec_points[p_id];
    let product = *p * secp256k1::Fr::from(scalar);
    let id = ec.ec_points.len();
    ec.ec_points.push(product.into());
    Ok(SyscallResult::Success(vec![id.into()]))
}

/// Executes the `secp256k1_get_point_from_x_syscall` syscall.
pub fn secp256k1_get_point_from_x(
    #[allow(unused)]
    gas_counter: &mut usize,
    x: BigUint,
    y_parity: bool,
    exec_scopes: &mut ExecutionScopes,
) -> Result<SyscallResult, HintError> {
    if x >= <secp256k1::Fq as PrimeField>::MODULUS.into() {
        fail_syscall!(b"Coordinates out of range        ");
    }
    let x = x.into();
    let maybe_p = secp256k1::Affine::get_ys_from_x_unchecked(x)
        .map(
            |(smaller, greater)|
            // Return the correct y coordinate based on the parity.
            if smaller.into_bigint().is_odd() == y_parity { smaller } else { greater },
        )
        .map(|y| secp256k1::Affine::new_unchecked(x, y))
        .filter(|p| p.is_in_correct_subgroup_assuming_on_curve());
    let Some(p) = maybe_p else {
        return Ok(SyscallResult::Success(vec![1.into(), 0.into()]));
    };
    let ec = get_secp256k1_exec_scope(exec_scopes)?;
    let id = ec.ec_points.len();
    ec.ec_points.push(p);
    Ok(SyscallResult::Success(vec![0.into(), id.into()]))
}

/// Executes the `secp256k1_get_xy_syscall` syscall.
pub fn secp256k1_get_xy(
    #[allow(unused)]
    gas_counter: &mut usize,
    p_id: usize,
    exec_scopes: &mut ExecutionScopes,
) -> Result<SyscallResult, HintError> {
    let ec = get_secp256k1_exec_scope(exec_scopes)?;
    let p = &ec.ec_points[p_id];
    let pow_2_128 = BigUint::from(u128::MAX) + 1u32;
    let (x1, x0) = BigUint::from(p.x).div_rem(&pow_2_128);
    let (y1, y0) = BigUint::from(p.y).div_rem(&pow_2_128);
    Ok(SyscallResult::Success(vec![
        Felt::from(x0).into(),
        Felt::from(x1).into(),
        Felt::from(y0).into(),
        Felt::from(y1).into(),
    ]))
}

/// Helper object to allocate and track Secp256k1 elliptic curve points.
#[derive(Default)]
struct Secp256k1ExecutionScope {
    /// All elliptic curve points provided by the secp256k1 syscalls.
    /// The id of a point is the index in the vector.
    ec_points: Vec<secp256k1::Affine>,
}

/// Returns the `Secp256k1ExecScope` managing the different active points.
/// The first call to this function will create the scope, and subsequent calls will return it.
/// The first call would happen from some point creation syscall.
fn get_secp256k1_exec_scope(
    exec_scopes: &mut ExecutionScopes,
) -> Result<&mut Secp256k1ExecutionScope, HintError> {
    const NAME: &str = "secp256k1_exec_scope";
    if exec_scopes
        .get_ref::<Secp256k1ExecutionScope>(NAME)
        .is_err()
    {
        exec_scopes.assign_or_update_variable(NAME, Box::<Secp256k1ExecutionScope>::default());
    }
    exec_scopes.get_mut_ref::<Secp256k1ExecutionScope>(NAME)
}
