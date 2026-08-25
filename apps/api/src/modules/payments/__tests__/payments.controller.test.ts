import { describe, it, expect, vi, beforeEach } from 'vitest';
import { PaymentsController } from '../payments.controller';
import { paymentsService } from '../payments.service';

vi.mock('../payments.service', () => ({
  paymentsService: {
    getPaymentsSummary: vi.fn(),
    getPayments: vi.fn(),
  }
}));

describe('PaymentsController', () => {
  let paymentsController: PaymentsController;
  let mockRequest: any;
  let mockReply: any;

  beforeEach(() => {
    paymentsController = new PaymentsController();
    vi.clearAllMocks();
    
    mockReply = {
      status: vi.fn().mockReturnThis(),
      send: vi.fn(),
    };
  });

  describe('getPaymentsSummary', () => {
    it('should return 400 if walletId is missing', async () => {
      mockRequest = { query: {} };
      
      await paymentsController.getPaymentsSummary(mockRequest, mockReply);
      
      expect(mockReply.status).toHaveBeenCalledWith(400);
      expect(mockReply.send).toHaveBeenCalledWith(expect.objectContaining({ error: 'Invalid query' }));
    });

    it('should return volume and count for a valid walletId', async () => {
      mockRequest = { query: { walletId: 'wallet_123' } };
      const mockSummary = { volume: 1500, count: 5 };
      
      vi.mocked(paymentsService.getPaymentsSummary).mockResolvedValue(mockSummary);
      
      await paymentsController.getPaymentsSummary(mockRequest, mockReply);
      
      expect(paymentsService.getPaymentsSummary).toHaveBeenCalledWith('wallet_123');
      expect(mockReply.send).toHaveBeenCalledWith({ success: true, summary: mockSummary });
    });
  });
});
