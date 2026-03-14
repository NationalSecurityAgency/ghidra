const isBooleanable = function (value: any): boolean {
  switch (Object.prototype.toString.call(value)) {
    case '[object String]':
      return [
        'true', 't', 'yes', 'y', 'on', '1',
        'false', 'f', 'no', 'n', 'off', '0'
      ].includes(value.trim().toLowerCase());

    case '[object Number]':
      return [ 0, 1 ].includes(value.valueOf());

    case '[object Boolean]':
      return true;

    default:
      return false;
  }
};

export { isBooleanable };
