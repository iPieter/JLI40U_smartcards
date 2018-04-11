package be.msec;

public class DataUtils
{
    private static short MAX_UNSIGNED_BYTE_SIZE = 0xff;

    public static byte[] add( byte[] data1, byte[] data2 )
    {
        assert data1.length == data2.length;

        byte[] result = new byte[ data1.length ];

        short overflow = 0;
        for ( short i = (short)( (short)(data1.length) - (short)(1) ); i >= 0; i-- )
        {
            short v = (short ) (( (short ) data1[ i ] & MAX_UNSIGNED_BYTE_SIZE ) + ( (short)data2[ i ] & MAX_UNSIGNED_BYTE_SIZE ) + overflow);
            result[ i ] = ( byte ) v;
            overflow = (short )(v >>> 8);
        }
        return result;
    }
}
