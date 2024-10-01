#[macro_export]
macro_rules! impl_bidirectional_from_for_structs {
    ($src:ty, $dest:ty,
     Direct [$( $field_direct:ident ),*],
     Into [$( $field_into:ident ),*],
     OptionInto [$( $field_option_into:ident ),*],
     OptionVecInto [$( $field_option_vec_into:ident ),*]
    ) => {
        impl From<$src> for $dest {
            fn from(item: $src) -> Self {
                Self {
                    $( $field_direct: item.$field_direct, )*
                    $( $field_into: item.$field_into.into(), )*
                    $( $field_option_into: item.$field_option_into.map(|x| x.into()), )*
                    $( $field_option_vec_into: item.$field_option_vec_into.map(|vec| vec.into_iter().map(|x| x.into()).collect()), )*
                }
            }
        }

        impl From<&$src> for $dest {
            fn from(item: &$src) -> Self {
                Self {
                    $( $field_direct: item.$field_direct.clone(), )*
                    $( $field_into: item.$field_into.clone().into(), )*
                    $( $field_option_into: item.$field_option_into.clone().map(|x| x.into()), )*
                    $( $field_option_vec_into: item.$field_option_vec_into.clone().map(|vec| vec.into_iter().map(|x| x.into()).collect()), )*
                }
            }
        }

        impl From<$dest> for $src {
            fn from(item: $dest) -> Self {
                Self {
                    $( $field_direct: item.$field_direct, )*
                    $( $field_into: item.$field_into.into(), )*
                    $( $field_option_into: item.$field_option_into.map(|x| x.into()), )*
                    $( $field_option_vec_into: item.$field_option_vec_into.map(|vec| vec.into_iter().map(|x| x.into()).collect()), )*
                }
            }
        }

        impl From<&$dest> for $src {
            fn from(item: &$dest) -> Self {
                Self {
                    $( $field_direct: item.$field_direct.clone(), )*
                    $( $field_into: item.$field_into.clone().into(), )*
                    $( $field_option_into: item.$field_option_into.clone().map(|x| x.into()), )*
                    $( $field_option_vec_into: item.$field_option_vec_into.clone().map(|vec| vec.into_iter().map(|x| x.into()).collect()), )*
                }
            }
        }
    };
}

#[macro_export]
macro_rules! impl_bidirectional_from_for_enum {
    ($SrcEnum:ident, $DestEnum:ident, { $($SrcVariant:ident => $DestVariant:ident),* }) => {
        // From $SrcEnum to $DestEnum (owned values)
        impl From<$SrcEnum> for $DestEnum {
            fn from(item: $SrcEnum) -> Self {
                match item {
                    $(
                        $SrcEnum::$SrcVariant(data) => $DestEnum::$DestVariant(data.into()),
                    )*
                }
            }
        }

        // From &$SrcEnum to $DestEnum (references)
        impl From<&$SrcEnum> for $DestEnum {
            fn from(item: &$SrcEnum) -> Self {
                match item {
                    $(
                        $SrcEnum::$SrcVariant(data) => $DestEnum::$DestVariant(data.clone().into()),
                    )*
                }
            }
        }

        // From $DestEnum to $SrcEnum (owned values)
        impl From<$DestEnum> for $SrcEnum {
            fn from(item: $DestEnum) -> Self {
                match item {
                    $(
                        $DestEnum::$DestVariant(data) => $SrcEnum::$SrcVariant(data.into()),
                    )*
                }
            }
        }

        // From &$DestEnum to $SrcEnum (references)
        impl From<&$DestEnum> for $SrcEnum {
            fn from(item: &$DestEnum) -> Self {
                match item {
                    $(
                        $DestEnum::$DestVariant(data) => $SrcEnum::$SrcVariant(data.clone().into()),
                    )*
                }
            }
        }
    };
}
