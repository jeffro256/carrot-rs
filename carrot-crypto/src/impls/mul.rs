macro_rules! impl_scalar_scalar_mul {
    ($lhs: ident, $rhs:ident, $prod:ident) => {
        impl Mul<$rhs> for $lhs {
            type Output = $prod;
            fn mul(self, rhs: $rhs) -> Self::Output {
                $prod::from_scalar(self.as_scalar_ref() * rhs.as_scalar_ref())
            }
        }
    };
}

//impl_scalar_scalar_mul!{}